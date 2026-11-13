//! The proxy (stub while the lane builds it).
pub struct Config;
pub struct Egress;
pub type Sink = std::sync::Arc<dyn Fn(Vec<derm_core::event::Event>) + Send + Sync>;
