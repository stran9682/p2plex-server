mod access_control;
pub mod viewer;

pub use access_control::AccessControl;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Request {
    pub namespace: String,
    pub resource: String,
    pub filename: String,
}

impl Request {
    pub fn new(namespace: String, resource: String, filename: String) -> Self {
        Request {
            namespace,
            resource,
            filename,
        }
    }
}
