//! Official RFC 9381 Appendix B.4 test vectors for
//! ECVRF-EDWARDS25519-SHA512-ELL2.

use kaspa_portal::{
    randomness::vrf::{VrfProof, VrfPublicKey, VrfSecretKey},
    KaspaPortal,
};

struct Vector {
    secret: &'static str,
    public: &'static str,
    alpha: &'static str,
    proof: &'static str,
    beta: &'static str,
}

const VECTORS: &[Vector] = &[
    Vector {
        secret: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        public: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        alpha: "",
        proof: "7d9c633ffeee27349264cf5c667579fc583b4bda63ab71d001f89c10003ab46f14adf9a3cd8b8412d9038531e865c341cafa73589b023d14311c331a9ad15ff2fb37831e00f0acaa6d73bc9997b06501",
        beta: "9d574bf9b8302ec0fc1e21c3ec5368269527b87b462ce36dab2d14ccf80c53cccf6758f058c5b1c856b116388152bbe509ee3b9ecfe63d93c3b4346c1fbc6c54",
    },
    Vector {
        secret: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        public: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        alpha: "72",
        proof: "47b327393ff2dd81336f8a2ef10339112401253b3c714eeda879f12c509072ef055b48372bb82efbdce8e10c8cb9a2f9d60e93908f93df1623ad78a86a028d6bc064dbfc75a6a57379ef855dc6733801",
        beta: "38561d6b77b71d30eb97a062168ae12b667ce5c28caccdf76bc88e093e4635987cd96814ce55b4689b3dd2947f80e59aac7b7675f8083865b46c89b2ce9cc735",
    },
    Vector {
        secret: "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        public: "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        alpha: "af82",
        proof: "926e895d308f5e328e7aa159c06eddbe56d06846abf5d98c2512235eaa57fdce35b46edfc655bc828d44ad09d1150f31374e7ef73027e14760d42e77341fe05467bb286cc2c9d7fde29120a0b2320d04",
        beta: "121b7f9b9aaaa29099fc04a94ba52784d44eac976dd1a3cca458733be5cd090a7b5fbd148444f17f8daf1fb55cb04b1ae85a626e30a54b4b0f8abf4a43314a58",
    },
];

#[test]
fn official_appendix_b4_vectors_match_public_api() {
    let portal = KaspaPortal::builder().build().unwrap();
    let vrf = portal.randomness().vrf();
    for vector in VECTORS {
        verify_vector(vrf, vector);
    }
}

#[test]
fn official_proofs_reject_modified_input() {
    let portal = KaspaPortal::builder().build().unwrap();
    let vector = &VECTORS[1];
    let public = VrfPublicKey(bytes32(vector.public));
    let proof = VrfProof(hex::decode(vector.proof).unwrap());
    assert!(portal.randomness().vrf().verify(&public, b"s", &proof).is_err());
}

fn verify_vector(vrf: &kaspa_portal::randomness::vrf::VrfApi, vector: &Vector) {
    let secret = VrfSecretKey::from_bytes(bytes32(vector.secret));
    let public = VrfPublicKey(bytes32(vector.public));
    let alpha = hex::decode(vector.alpha).unwrap();
    let proof = hex::decode(vector.proof).unwrap();
    assert_eq!(secret.public_key(), public);
    let generated = vrf.prove(&secret, &alpha).unwrap();
    assert_eq!(generated.proof.0, proof);
    assert_eq!(hex::encode(&generated.output.0), vector.beta);
    let verified = vrf.verify(&public, &alpha, &VrfProof(proof)).unwrap();
    assert_eq!(hex::encode(verified.0), vector.beta);
}

fn bytes32(value: &str) -> [u8; 32] {
    hex::decode(value).unwrap().try_into().unwrap()
}
