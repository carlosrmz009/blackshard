//! Parser surfaces shared with fuzzing and external evaluation harnesses.

pub mod amsi;
pub mod archive;
pub mod atomic_file;
pub mod behavior;
pub mod config;
pub mod definitions;
pub mod detection;
pub mod driver_installer;
pub mod elevation;
pub mod engine;
pub mod history;
pub mod ipc;
pub mod model;
pub mod notification_agent;
pub mod notifications;
pub mod quarantine;
pub mod readiness;
pub mod realtime;
pub mod rules;
pub mod scan_manager;
pub mod self_test;
pub mod service;
pub mod similarity;
pub mod trust;
pub mod ui;
pub mod update_client;
pub mod updater;
pub mod vba;
pub mod verdict_cache;

pub mod clamav_worker;
pub mod freshclam;
pub mod parser_worker;
