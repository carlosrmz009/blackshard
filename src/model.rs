#[derive(Debug, Clone, PartialEq)]
pub struct ModelFeatures {
    pub entropy: f32,
    pub section_count: f32,
    pub import_count: f32,
    pub is_pe: f32,
}

impl Default for ModelFeatures {
    fn default() -> Self {
        Self {
            entropy: 0.0,
            section_count: 0.0,
            import_count: 0.0,
            is_pe: 0.0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DecisionTreeEnsemble {
    pub version: u32,
}

impl Default for DecisionTreeEnsemble {
    fn default() -> Self {
        Self { version: 1 }
    }
}

impl DecisionTreeEnsemble {
    pub fn new(version: u32) -> Self {
        Self { version }
    }

    /// Evaluates the extracted features. Returns a float score.
    pub fn evaluate(&self, features: &ModelFeatures) -> f32 {
        let mut score = 0.0;

        // Very basic placeholder inference rules
        if features.is_pe > 0.0 {
            if features.entropy > 7.0 {
                score += 30.0;
            }
            if features.section_count > 10.0 {
                score += 10.0;
            }
            score += (features.import_count / 100.0).min(20.0);
        }

        score
    }
}

#[derive(Debug, Clone)]
pub struct ModelManager {
    active_model: DecisionTreeEnsemble,
    previous_model: Option<DecisionTreeEnsemble>,
}

impl Default for ModelManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ModelManager {
    pub fn new() -> Self {
        Self {
            active_model: DecisionTreeEnsemble::default(),
            previous_model: None,
        }
    }

    pub fn update_model(&mut self, new_model: DecisionTreeEnsemble) {
        self.previous_model = Some(self.active_model.clone());
        self.active_model = new_model;
    }

    pub fn rollback(&mut self) -> Result<(), &'static str> {
        if let Some(prev) = self.previous_model.take() {
            self.active_model = prev;
            Ok(())
        } else {
            Err("No previous model to roll back to.")
        }
    }

    pub fn active(&self) -> &DecisionTreeEnsemble {
        &self.active_model
    }
}
