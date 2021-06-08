extern crate cfd_rust;
extern crate sha2;

#[cfg(test)]
mod tests {
  use cfd_rust::{
    AdaptorSignature, ByteData, Privkey, Pubkey, SchnorrPubkey, SchnorrSignature, SchnorrUtil,
  };
  use std::str::FromStr;

  #[test]
  fn ecdsa_adaptor_test() {
    // default
    let msg =
      ByteData::from_str("8131e6f4b45754f2c90bd06688ceeabc0c45055460729928b4eecf11026a9e2d")
        .expect("Fail");
    let adaptor =
      Pubkey::from_str("02042537e913ad74c4bbd8da9607ad3b9cb297d08e014afc51133083f1bd687a62")
        .expect("Fail");
    let sk = Privkey::from_str("90ac0d5dc0a1a9ab352afb02005a5cc6c4df0da61d8149d729ff50db9b5a5215")
      .expect("Fail");
    let pubkey =
      Pubkey::from_str("03490cec9a53cd8f2f664aea61922f26ee920c42d2489778bb7c9d9ece44d149a7")
        .expect("Fail");
    let adaptor_sig =
    AdaptorSignature::from_str("0287b498de89db75bf68e15836be75e42619cfe85a6bcea503ea23444597deae8c025ed1a6f5d7ce4a4d8132c824ed374353629d672fea7c5c459348f3b279463d5a8d6d61a6589bb4b99bbccc3c0cd288ec5826e42821326aa29d1ab0af3f344ff3a1c4e25ad6fe22e55786685f6266a2f57a771c33404829fbac39b5810fb52e3534070c08dcdb7be744cbde3cde979f9d79ecb9f155ecf3c4975bbc5935486f14").expect("Fail");

    let adaptor_sig2 =
    AdaptorSignature::from_str("032c637cd797dd8c2ce261907ed43e82d6d1a48cbabbbece801133dd8d70a01b1403eb615a3e59b1cbbf4f87acaf645be1eda32a066611f35dd5557802802b14b19c81c04c3fefac5783b2077bd43fa0a39ab8a64d4d78332a5d621ea23eca46bc011011ab82dda6deb85699f508744d70d4134bea03f784d285b5c6c15a56e4e1fab4bc356abbdebb3b8fe1e55e6dd6d2a9ea457e91b2e6642fae69f9dbb5258854").expect("Fail");
    let expect_sig = ByteData::from_str("2c637cd797dd8c2ce261907ed43e82d6d1a48cbabbbece801133dd8d70a01b144a0dbcde0aaf484622f911b03027d423e1fd99e71ba10f6f7232e52a1ca9d706").expect("Fail");
    let secret =
      Privkey::from_str("324719b51ff2474c9438eb76494b0dc0bcceeb529f0a5428fd198ad8f886e99c")
        .expect("Fail");

    let sig = AdaptorSignature::encrypt(&msg, &sk, &adaptor).expect("Fail");
    assert_eq!(adaptor_sig.to_hex(), sig.to_hex());

    let is_verify = sig.verify(&msg, &pubkey, &adaptor).expect("Fail");
    assert_eq!(true, is_verify);

    let signature = adaptor_sig2.decrypt(&secret).expect("Fail");
    assert_eq!(expect_sig.to_hex(), signature.to_hex());

    let adaptor_secret = adaptor_sig2.recover(&signature, &adaptor).expect("Fail");
    assert_eq!(secret.to_hex(), adaptor_secret.to_hex());
  }

  #[test]
  fn schnorr_util_test() {
    // default
    let msg =
      ByteData::from_str("e48441762fb75010b2aa31a512b62b4148aa3fb08eb0765d76b252559064a614")
        .expect("Fail");
    let sk = Privkey::from_str("688c77bc2d5aaff5491cf309d4753b732135470d05b7b2cd21add0744fe97bef")
      .expect("Fail");
    let pubkey =
      SchnorrPubkey::from_str("b33cc9edc096d0a83416964bd3c6247b8fecd256e4efa7870d2c854bdeb33390")
        .expect("Fail");
    let aux_rand =
      ByteData::from_str("02cce08e913f22a36c5648d6405a2c7c50106e7aa2f1649e381c7f09d16b80ab")
        .expect("Fail");
    let nonce =
      SchnorrPubkey::from_str("8c8ca771d3c25eb38de7401818eeda281ac5446f5c1396148f8d9d67592440fe")
        .expect("Fail");
    let schnorr_nonce =
      SchnorrPubkey::from_str("f14d7e54ff58c5d019ce9986be4a0e8b7d643bd08ef2cdf1099e1a457865b547")
        .expect("Fail");
    let signature =
    SchnorrSignature::from_str("6470fd1303dda4fda717b9837153c24a6eab377183fc438f939e0ed2b620e9ee5077c4a8b8dca28963d772a94f5f0ddf598e1c47c137f91933274c7c3edadce8").expect("Fail");

    let obj = SchnorrUtil::new();
    let sig1 = obj.sign(&msg, &sk, &aux_rand).expect("Fail");
    assert_eq!(signature.to_hex(), sig1.to_hex());

    let expected_sig =
    "5da618c1936ec728e5ccff29207f1680dcf4146370bdcfab0039951b91e3637a958e91d68537d1f6f19687cec1fd5db1d83da56ef3ade1f3c611babd7d08af42";
    let sig2 = obj
      .sign_with_nonce(&msg, &sk, &nonce.as_key().expect("Fail"))
      .expect("Fail");
    assert_eq!(expected_sig, sig2.to_hex());

    let expected_sig_point = "03735acf82eef9da1540efb07a68251d5476dabb11ac77054924eccbb4121885e8";
    let sig_point = obj
      .compute_sig_point(&msg, &schnorr_nonce, &pubkey)
      .expect("Fail");
    assert_eq!(expected_sig_point, sig_point.to_hex());

    let is_verify = obj.verify(&sig1, &msg, &pubkey).expect("Fail");
    assert_eq!(true, is_verify);

    let expected_nonce = "6470fd1303dda4fda717b9837153c24a6eab377183fc438f939e0ed2b620e9ee";
    let expected_privkey = "5077c4a8b8dca28963d772a94f5f0ddf598e1c47c137f91933274c7c3edadce8";
    assert_eq!(expected_nonce, sig1.as_nonce().to_hex());
    assert_eq!(expected_privkey, sig1.as_key().to_hex());
  }

  #[test]
  fn schnorr_pubkey_test() {
    // default
    let tweak =
      ByteData::from_str("e48441762fb75010b2aa31a512b62b4148aa3fb08eb0765d76b252559064a614")
        .expect("Fail");
    let sk = Privkey::from_str("688c77bc2d5aaff5491cf309d4753b732135470d05b7b2cd21add0744fe97bef")
      .expect("Fail");
    let pk = Pubkey::from_str("03b33cc9edc096d0a83416964bd3c6247b8fecd256e4efa7870d2c854bdeb33390")
      .expect("Fail");
    let pubkey =
      SchnorrPubkey::from_str("b33cc9edc096d0a83416964bd3c6247b8fecd256e4efa7870d2c854bdeb33390")
        .expect("Fail");
    let exp_tweaked_pk =
      SchnorrPubkey::from_str("1fc8e882e34cc7942a15f39ffaebcbdf58a19239bcb17b7f5aa88e0eb808f906")
        .expect("Fail");
    let exp_tweaked_sk =
      Privkey::from_str("7bf7c9ba025ca01b698d3e9b3e40efce2774f8a388f8c390550481e1407b2a25")
        .expect("Fail");

    let (schnorr_pubkey, parity) = SchnorrPubkey::from_privkey(&sk).expect("Fail");
    assert_eq!(pubkey.to_hex(), schnorr_pubkey.to_hex());
    assert_eq!(true, parity);

    let (schnorr_pubkey, parity) = SchnorrPubkey::from_pubkey(&pk).expect("Fail");
    assert_eq!(pubkey.to_hex(), schnorr_pubkey.to_hex());
    assert_eq!(true, parity);

    let (tweaked_pubkey, tweaked_parity) = pubkey.tweak_add(tweak.to_slice()).expect("Fail");
    assert_eq!(exp_tweaked_pk.to_hex(), tweaked_pubkey.to_hex());
    assert_eq!(true, tweaked_parity);

    let gen_key_ret =
      SchnorrPubkey::get_tweak_add_from_privkey(&sk, tweak.to_slice()).expect("Fail");
    let (tweaked_pubkey, tweaked_parity, tweaked_privkey) = gen_key_ret;
    assert_eq!(exp_tweaked_pk.to_hex(), tweaked_pubkey.to_hex());
    assert_eq!(true, tweaked_parity);
    assert_eq!(exp_tweaked_sk.to_hex(), tweaked_privkey.to_hex());

    let is_valid = tweaked_pubkey
      .is_tweaked(true, &pubkey, tweak.to_slice())
      .expect("Fail");
    assert_eq!(true, is_valid);
    let is_valid = tweaked_pubkey
      .is_tweaked(false, &pubkey, tweak.to_slice())
      .expect("Fail");
    assert_eq!(false, is_valid);
  }
}
