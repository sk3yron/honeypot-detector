#[cfg(feature = "ml-inference")]
use ort::{Environment, Session, SessionBuilder, Value};
#[cfg(feature = "ml-inference")]
use ndarray::{Array2, CowArray, IxDyn};
#[cfg(feature = "ml-inference")]
use std::sync::Arc;

use async_trait::async_trait;
use std::path::Path;
use std::collections::HashMap;

use crate::core::Analyzer;
use crate::features::FeatureExtractor;
use crate::models::*;
use crate::utils::{Result, DetectorError};

#[cfg(feature = "ml-inference")]
pub struct MLAnalyzer {
    model: Arc<Session>,
    scaler: Arc<Session>,
    feature_extractor: FeatureExtractor,
    metadata: ModelMetadata,
}

#[cfg(not(feature = "ml-inference"))]
pub struct MLAnalyzer;

#[derive(Debug, serde::Deserialize)]
struct ModelMetadata {
    feature_names: Vec<String>,
    n_features: usize,
    model_type: String,
    metrics: MetricsData,
}

#[derive(Debug, serde::Deserialize)]
struct MetricsData {
    #[serde(default)]
    test_accuracy: serde_json::Value,
    #[serde(default)]
    roc_auc: serde_json::Value,
}

#[cfg(feature = "ml-inference")]
impl MLAnalyzer {
    pub fn new<P: AsRef<Path>>(models_dir: P) -> Result<Self> {
        let models_dir = models_dir.as_ref();
        
        tracing::info!("Loading ML model from {:?}", models_dir);
        
        // Load metadata
        let metadata_path = models_dir.join("model_metadata.json");
        if !metadata_path.exists() {
            return Err(DetectorError::MLError(
                format!("Model metadata not found at {:?}", metadata_path)
            ));
        }
        
        let metadata: ModelMetadata = serde_json::from_str(
            &std::fs::read_to_string(metadata_path)?
        )?;
        
        tracing::info!("Model metadata loaded: {} features", metadata.n_features);
        
        // Initialize ONNX environment
        let environment = Arc::new(
            Environment::builder()
                .with_name("honeypot-detector")
                .build()
                .map_err(|e| DetectorError::MLError(format!("ONNX env error: {}", e)))?
        );
        
        // Load scaler
        let scaler_path = models_dir.join("scaler.onnx");
        if !scaler_path.exists() {
            return Err(DetectorError::MLError(
                format!("Scaler not found at {:?}", scaler_path)
            ));
        }
        
        let scaler = Arc::new(
            SessionBuilder::new(&environment)
                .map_err(|e| DetectorError::MLError(format!("Session builder error: {}", e)))?
                .with_model_from_file(scaler_path)
                .map_err(|e| DetectorError::MLError(format!("Failed to load scaler: {}", e)))?
        );
        
        tracing::info!("Scaler loaded");
        
        // Load model
        let model_path = models_dir.join("honeypot_model.onnx");
        if !model_path.exists() {
            return Err(DetectorError::MLError(
                format!("Model not found at {:?}", model_path)
            ));
        }
        
        let model = Arc::new(
            SessionBuilder::new(&environment)
                .map_err(|e| DetectorError::MLError(format!("Session builder error: {}", e)))?
                .with_model_from_file(model_path)
                .map_err(|e| DetectorError::MLError(format!("Failed to load model: {}", e)))?
        );
        
        tracing::info!("ML model loaded successfully");
        
        Ok(Self {
            model,
            scaler,
            feature_extractor: FeatureExtractor::new(),
            metadata,
        })
    }
    
    pub fn predict(&self, bytecode: &[u8]) -> Result<MLPrediction> {
        // Extract features
        let features = self.feature_extractor.extract_features(bytecode)?;
        
        // Convert to ordered array matching training
        let mut feature_vec = Vec::with_capacity(self.metadata.n_features);
        for name in &self.metadata.feature_names {
            let value = features.get(name).copied().unwrap_or(0.0);
            feature_vec.push(value);
        }
        
        // Create ndarray with dynamic dimensions for ort
        let input = Array2::from_shape_vec((1, self.metadata.n_features), feature_vec)
            .map_err(|e| DetectorError::MLError(format!("Shape error: {}", e)))?;
        
        // Scale features
        let scaled = self.scale_features(input)?;
        
        // Run inference
        let (is_honeypot, probabilities) = self.run_inference(scaled)?;
        
        let honeypot_prob = probabilities[1];
        let risk_score = (honeypot_prob * 100.0).min(100.0) as u8;
        
        Ok(MLPrediction {
            is_honeypot,
            risk_score,
            confidence: honeypot_prob as f64,
            honeypot_probability: honeypot_prob as f64,
            safe_probability: probabilities[0] as f64,
            risk_level: Self::risk_level_from_score(risk_score),
            detected_patterns: Self::extract_patterns(&features),
        })
    }
    
    fn scale_features(&self, input: Array2<f32>) -> Result<Array2<f32>> {
        // Convert to CowArray for ort
        let input_cow: CowArray<f32, IxDyn> = CowArray::from(input.into_dyn());
        
        let input_value = Value::from_array(self.scaler.allocator(), &input_cow)
            .map_err(|e| DetectorError::MLError(format!("Failed to create input value: {}", e)))?;
        
        let outputs = self.scaler.run(vec![input_value])
            .map_err(|e| DetectorError::MLError(format!("Scaler inference failed: {}", e)))?;
        
        // Extract output
        let scaled_dyn = outputs[0].try_extract::<f32>()
            .map_err(|e| DetectorError::MLError(format!("Failed to extract scaled output: {}", e)))?;
        
        // Convert back to Array2
        let scaled_view = scaled_dyn.view();
        let shape = scaled_view.shape();
        let scaled_vec: Vec<f32> = scaled_view.iter().copied().collect();
        
        Array2::from_shape_vec((shape[0], shape[1]), scaled_vec)
            .map_err(|e| DetectorError::MLError(format!("Failed to reshape scaled output: {}", e)))
    }

    fn run_inference(&self, input: Array2<f32>) -> Result<(bool, [f32; 2])> {
        // Convert to CowArray for ort
        let input_cow: CowArray<f32, IxDyn> = CowArray::from(input.into_dyn());
        
        let input_value = Value::from_array(self.model.allocator(), &input_cow)
            .map_err(|e| DetectorError::MLError(format!("Failed to create input: {}", e)))?;
        
        let outputs = self.model.run(vec![input_value])
            .map_err(|e| DetectorError::MLError(format!("Model inference failed: {}", e)))?;
        
        // XGBoost ONNX output: [label, probabilities]
        let label_output = outputs[0].try_extract::<i64>()
            .map_err(|e| DetectorError::MLError(format!("Failed to extract label: {}", e)))?;
        
        let probs_output = outputs[1].try_extract::<f32>()
            .map_err(|e| DetectorError::MLError(format!("Failed to extract probabilities: {}", e)))?;
        
        // Get label (first element)
        let label = label_output.view()[[0]];
        
        // Get probabilities
        let probs_view = probs_output.view();
        let probabilities = [probs_view[[0, 0]], probs_view[[0, 1]]];
        
        Ok((label == 1, probabilities))
    }
    
    fn extract_patterns(features: &HashMap<String, f32>) -> Vec<String> {
        let mut patterns = Vec::new();
        
        if features.get("has_blacklist_functions").copied().unwrap_or(0.0) > 0.0 {
            patterns.push("Blacklist mechanism detected".to_string());
        }
        
        if features.get("has_approve_no_transferfrom").copied().unwrap_or(0.0) > 0.0 {
            patterns.push("Broken ERC20: approve without transferFrom".to_string());
        }
        
        if features.get("missing_transfer").copied().unwrap_or(0.0) > 0.0 {
            patterns.push("Missing transfer function".to_string());
        }
        
        if features.get("delegatecall_to_storage_pattern").copied().unwrap_or(0.0) > 0.0 {
            patterns.push("DELEGATECALL to storage address".to_string());
        }
        
        if features.get("hidden_owner_checks").copied().unwrap_or(0.0) > 0.0 {
            patterns.push("Hidden ownership checks".to_string());
        }
        
        patterns
    }
    
    fn risk_level_from_score(score: u8) -> String {
        match score {
            80..=100 => "CRITICAL",
            60..=79 => "HIGH",
            40..=59 => "MEDIUM",
            20..=39 => "LOW",
            _ => "SAFE",
        }.to_string()
    }
}

#[cfg(not(feature = "ml-inference"))]
impl MLAnalyzer {
    pub fn new<P: AsRef<Path>>(_models_dir: P) -> Result<Self> {
        Err(DetectorError::MLError(
            "ML inference not enabled. Build with: cargo build --features ml-inference".to_string()
        ))
    }
}

#[async_trait]
impl Analyzer for MLAnalyzer {
    fn name(&self) -> &'static str {
        "ml-bytecode-analysis"
    }
    
    #[cfg(feature = "ml-inference")]
    async fn analyze(&self, target: &ContractTarget) -> Result<AnalysisResult> {
        let bytecode = target.bytecode.as_ref()
            .ok_or_else(|| DetectorError::AnalysisError(
                "ML analyzer requires bytecode".into()
            ))?;
        
        tracing::info!("Running ML analysis on {} bytes", bytecode.len());
        
        let prediction = self.predict(bytecode)?;
        
        tracing::info!("ML prediction: {} ({}%)", 
            if prediction.is_honeypot { "HONEYPOT" } else { "SAFE" },
            prediction.risk_score
        );
        
        let mut metadata = HashMap::new();
        metadata.insert("ml_confidence".to_string(), serde_json::json!(prediction.confidence));
        metadata.insert("ml_risk_level".to_string(), serde_json::json!(prediction.risk_level));
        metadata.insert("ml_model_accuracy".to_string(), self.metadata.metrics.test_accuracy.clone());
        metadata.insert("ml_model_roc_auc".to_string(), self.metadata.metrics.roc_auc.clone());
        
        Ok(AnalysisResult {
            risk_score: prediction.risk_score,
            findings: prediction.to_findings(),
            metadata,
        })
    }
    
    #[cfg(not(feature = "ml-inference"))]
    async fn analyze(&self, _target: &ContractTarget) -> Result<AnalysisResult> {
        Err(DetectorError::MLError(
            "ML inference not enabled".to_string()
        ))
    }
    
    fn weight(&self) -> f64 {
        0.30  // 30% weight in ensemble
    }
}

#[derive(Debug)]
pub struct MLPrediction {
    pub is_honeypot: bool,
    pub risk_score: u8,
    pub confidence: f64,
    pub honeypot_probability: f64,
    pub safe_probability: f64,
    pub risk_level: String,
    pub detected_patterns: Vec<String>,
}

impl MLPrediction {
    pub fn to_findings(&self) -> Vec<Finding> {
        let mut findings = vec![];
        
        // Overall assessment
        findings.push(Finding {
            severity: Severity::from_score(self.risk_score),
            category: Category::MLPattern,
            message: format!(
                "ML model: {} risk (confidence: {:.1}%)",
                self.risk_level, self.confidence * 100.0
            ),
            evidence: Some(serde_json::json!({
                "risk_score": self.risk_score,
                "honeypot_probability": self.honeypot_probability,
            })),
        });
        
        // Specific patterns
        for pattern in &self.detected_patterns {
            let severity = if pattern.contains("Blacklist") || pattern.contains("Broken ERC20") {
                Severity::Critical
            } else if pattern.contains("DELEGATECALL") {
                Severity::High
            } else {
                Severity::Medium
            };
            
            findings.push(Finding {
                severity,
                category: Category::MLPattern,
                message: pattern.clone(),
                evidence: None,
            });
        }
        
        findings
    }
}