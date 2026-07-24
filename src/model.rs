#[derive(Debug, Clone, PartialEq)]
pub struct HeuristicFeatures {
    pub entropy: f32,
    pub section_count: f32,
    pub import_count: f32,
    pub is_pe: f32,
}

impl Default for HeuristicFeatures {
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
/// Versioned, deterministic static heuristic. This is deliberately not
/// described as machine learning: it has no trained model artifact or measured
/// calibration data.
pub struct StaticHeuristic {
    pub version: u32,
}

impl Default for StaticHeuristic {
    fn default() -> Self {
        Self { version: 1 }
    }
}

impl StaticHeuristic {
    pub fn new(version: u32) -> Self {
        Self { version }
    }

    /// Evaluates the extracted features. Returns a float score.
    pub fn evaluate(&self, features: &HeuristicFeatures) -> f32 {
        let mut score = 0.0;

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
pub struct HeuristicManager {
    active_model: StaticHeuristic,
    previous_model: Option<StaticHeuristic>,
}

impl Default for HeuristicManager {
    fn default() -> Self {
        Self::new()
    }
}

impl HeuristicManager {
    pub fn new() -> Self {
        Self {
            active_model: StaticHeuristic::default(),
            previous_model: None,
        }
    }

    pub fn update_model(&mut self, new_model: StaticHeuristic) {
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

    pub fn active(&self) -> &StaticHeuristic {
        &self.active_model
    }
}
