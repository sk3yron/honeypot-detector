// src/analyzers/ml_analyzer.rs

use ndarray::{Array1, Array2};
use ort::{Environment, Session, SessionBuilder, Value};
use std::path::Path;
use std::sync::Arc;

use crate::core::Analyzer;
use crate::features::FeatureExtractor;
use crate::models::*;
use crate::utils::errors::{Result, DetectorError};

pub struct MLAnalyzer {
    model: Arc<Session>,
    scaler: Arc<Session>,
    feature_extractor: FeatureExtractor,
    feature_names: Vec<String>,
    metadata: ModelMetadata,
}

#[derive(Debug, serde::Deserialize)]
struct ModelMetadata {
    feature_names: Vec<String>,
    n_features: usize,
    model_type: String,
    metrics: serde_json::Value,
}

impl MLAnalyzer {
    pub fn new<P: AsRef<Path>>(models_dir: P) -> Result<Self> {
        let models_dir = models_dir.as_ref();
        
        // Load metadata
        let metadata_path = models_dir.join("model_metadata.json");
        let metadata: ModelMetadata = serde_json::from_str(
            &std::fs::read_to_string(metadata_path)?
        )?;
        
        // Initialize ONNX Runtime
        let environment = Arc::new(
            Environment::builder()
                .with_name("honeypot-detector")
                .build()?
        );
        
        // Load scaler
        let scaler_path = models_dir.join("scaler.onnx");
        let scaler = Arc::new(
            SessionBuilder::new(&environment)?
                .with_model_from_file(scaler_path)?
        );
        
        // Load model
        let model_path = models_dir.join("honeypot_model.onnx");
        let model = Arc::new(
            SessionBuilder::new(&environment)?
                .with_model_from_file(model_path)?
        );
        
        Ok(Self {
            model,
            scaler,
            feature_extractor: FeatureExtractor::new(),
            feature_names: metadata.feature_names.clone(),
            metadata,
        })
    }
    
    /// Extract features and run inference
    pub fn predict(&self, bytecode: &[u8]) -> Result<MLPrediction> {
        // 1. Extract features (Rust implementation)
        let features = self.feature_extractor.extract_all_features(bytecode)?;
        
        // 2. Convert to array in correct order
        let feature_array: Vec<f32> = self.feature_names
            .iter()
            .map(|name| *features.get(name).unwrap_or(&0.0) as f32)
            .collect();
        
        let n_features = self.metadata.n_features;
        let input = Array2::from_shape_vec((1, n_features), feature_array)?;
        
        // 3. Scale features
        let scaled = self.scale_features(input)?;
        
        // 4. Run model inference
        let (is_honeypot, probabilities) = self.run_inference(scaled)?;
        
        // 5. Extract top risk features
        let top_features = self.identify_top_risk_features(&features);
        
        let honeypot_prob = probabilities[1];
        let risk_score = (honeypot_prob * 100.0) as u8;
        
        Ok(MLPrediction {
            is_honeypot,
            risk_score,
            confidence: honeypot_prob as f64,
            honeypot_probability: honeypot_prob as f64,
            safe_probability: probabilities[0] as f64,
            risk_level: Self::risk_level_from_score(risk_score),
            top_risk_features: top_features,
        })
    }
    
    fn scale_features(&self, input: Array2<f32>) -> Result<Array2<f32>> {
        let input_value = Value::from_array(self.scaler.allocator(), &input)?;
        
        let outputs = self.scaler.run(vec![input_value])?;
        let scaled: ndarray::ArrayView2<f32> = outputs[0].try_extract()?;
        
        Ok(scaled.to_owned())
    }
    
    fn run_inference(&self, input: Array2<f32>) -> Result<(bool, [f32; 2])> {
        let input_value = Value::from_array(self.model.allocator(), &input)?;
        
        let outputs = self.model.run(vec![input_value])?;
        
        // XGBoost output: [label, probabilities]
        let label: i64 = outputs[0].try_extract::<i64>()?.into_scalar();
        let probs: ndarray::ArrayView2<f32> = outputs[1].try_extract()?;
        
        let probabilities = [probs[[0, 0]], probs[[0, 1]]];
        
        Ok((label == 1, probabilities))
    }
    
    fn identify_top_risk_features(
        &self,
        features: &HashMap<String, f64>
    ) -> Vec<RiskFeature> {
        // Known high-risk features (from your Python feature importance)
        let risk_patterns = [
            ("has_blacklist_functions", "Blacklist mechanism detected"),
            ("has_approve_no_transferfrom", "Broken ERC20: approve without transferFrom"),
            ("missing_transfer", "Missing transfer function"),
            ("delegatecall_to_storage_pattern", "DELEGATECALL to storage address"),
            ("conditional_selfdestruct", "Conditional self-destruct"),
            ("hidden_owner_checks", "Hidden ownership checks"),
            ("max_jumpi_before_transfer", "Complex transfer conditions"),
        ];
        
        risk_patterns
            .iter()
            .filter_map(|(feature, desc)| {
                features.get(*feature).and_then(|&value| {
                    if value > 0.0 {
                        Some(RiskFeature {
                            name: feature.to_string(),
                            value,
                            description: desc.to_string(),
                        })
                    } else {
                        None
                    }
                })
            })
            .collect()
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

#[async_trait]
impl Analyzer for MLAnalyzer {
    fn name(&self) -> &'static str {
        "ml-bytecode-analysis"
    }
    
    async fn analyze(&self, target: &ContractTarget) -> Result<AnalysisResult> {
        let bytecode = target.bytecode.as_ref()
            .ok_or_else(|| DetectorError::AnalysisError(
                "ML analyzer requires bytecode".into()
            ))?;
        
        let prediction = self.predict(bytecode)?;
        
        Ok(AnalysisResult {
            risk_score: prediction.risk_score,
            findings: prediction.to_findings(),
            metadata: hashmap! {
                "ml_confidence" => json!(prediction.confidence),
                "ml_risk_level" => json!(prediction.risk_level),
            },
        })
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
    pub top_risk_features: Vec<RiskFeature>,
}

#[derive(Debug, Clone)]
pub struct RiskFeature {
    pub name: String,
    pub value: f64,
    pub description: String,
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
            evidence: None,
        });
        
        // Specific patterns
        for feature in &self.top_risk_features {
            findings.push(Finding {
                severity: Severity::from_description(&feature.description),
                category: Category::MLPattern,
                message: feature.description.clone(),
                evidence: Some(json!({
                    "feature": feature.name,
                    "value": feature.value,
                })),
            });
        }
        
        findings
    }
}
