use iroh::Endpoint;
use iroh_blobs::store::mem::MemStore;

#[derive(Debug, Clone)]
pub struct IrohMemInstance {
    store: MemStore,
    endpoint: Endpoint,
}

impl IrohMemInstance {
    pub fn new(store: MemStore, endpoint: Endpoint) -> Self {
        Self { store, endpoint }
    }
}

impl IrohMemInstance {
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    pub fn blobs(&self) -> &iroh_blobs::api::Store {
        &self.store
    }
}
