use crate::randomness::{beacon::BeaconApi, source::curby::CurbyClient, vrf::VrfApi};

#[derive(Clone)]
pub struct RandomnessApi {
    beacon: BeaconApi,
    vrf: VrfApi,
}

impl RandomnessApi {
    pub(crate) fn new(curby: CurbyClient) -> Self {
        Self {
            beacon: BeaconApi::new(curby),
            vrf: VrfApi::new(),
        }
    }

    pub fn beacon(&self) -> &BeaconApi {
        &self.beacon
    }

    pub fn vrf(&self) -> &VrfApi {
        &self.vrf
    }
}
