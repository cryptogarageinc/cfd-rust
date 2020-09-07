extern crate cfd_sys;
extern crate libc;

use self::libc::c_char;
use crate::common::{
  alloc_c_string, byte_from_hex, collect_cstring_and_free, collect_multi_cstring_and_free,
  copy_array_32byte, hex_from_bytes, ByteData, CfdError, ErrorHandle,
};
use crate::key::{Privkey, Pubkey};
use std::fmt;
use std::ptr;
use std::result::Result::{Err, Ok};
use std::str::FromStr;

use self::cfd_sys::{
  CfdAdaptEcdsaAdaptor, CfdComputeSchnorrSigPoint, CfdExtractEcdsaAdaptorSecret,
  CfdSignEcdsaAdaptor, CfdSignSchnorr, CfdSignSchnorrWithNonce, CfdSplitSchnorrSignature,
  CfdVerifyEcdsaAdaptor, CfdVerifySchnorr,
};

/// adaptor signature size.
pub const ADAPTOR_SIGNATURE_SIZE: usize = 65;
/// adaptor proof size.
pub const ADAPTOR_PROOF_SIZE: usize = 97;
/// schnorr nonce size.
pub const SCHNORR_NONCE_SIZE: usize = 32;
/// schnorr signature size.
pub const SCHNORR_SIGNATURE_SIZE: usize = 64;

/// A container that stores a public key.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AdaptorSignature {
  data: Vec<u8>,
}

impl AdaptorSignature {
  /// Generate from slice.
  ///
  /// # Arguments
  /// * `key` - A public key bytes
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::AdaptorSignature;
  /// let bytes = [2; 65];
  /// let sig = AdaptorSignature::from_slice(&bytes).expect("Fail");
  /// ```
  pub fn from_slice(data: &[u8]) -> Result<AdaptorSignature, CfdError> {
    AdaptorSignature::from_vec(data.to_vec())
  }

  /// Generate from vector.
  ///
  /// # Arguments
  /// * `key` - A public key vector
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::AdaptorSignature;
  /// let bytes = [2; 65];
  /// let sig = AdaptorSignature::from_vec(bytes.to_vec()).expect("Fail");
  /// ```
  pub fn from_vec(data: Vec<u8>) -> Result<AdaptorSignature, CfdError> {
    match data.len() {
      ADAPTOR_SIGNATURE_SIZE => Ok(AdaptorSignature { data }),
      _ => Err(CfdError::IllegalArgument(
        "invalid pubkey format.".to_string(),
      )),
    }
  }

  #[inline]
  pub fn to_slice(&self) -> &[u8] {
    &self.data
  }

  #[inline]
  pub fn to_hex(&self) -> String {
    hex_from_bytes(&self.data)
  }

  #[inline]
  pub fn to_str(&self) -> String {
    self.to_hex()
  }
}

impl fmt::Display for AdaptorSignature {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    let s = hex::encode(&self.data);
    write!(f, "{}", s)
  }
}

impl FromStr for AdaptorSignature {
  type Err = CfdError;
  fn from_str(text: &str) -> Result<AdaptorSignature, CfdError> {
    match byte_from_hex(text) {
      Ok(byte_array) => AdaptorSignature::from_vec(byte_array),
      Err(e) => Err(e),
    }
  }
}

impl Default for AdaptorSignature {
  fn default() -> AdaptorSignature {
    AdaptorSignature { data: vec![] }
  }
}

/// A container that stores An adaptor proof.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AdaptorProof {
  data: Vec<u8>,
}

impl AdaptorProof {
  /// Generate from slice.
  ///
  /// # Arguments
  /// * `data` - A proof bytes
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::AdaptorProof;
  /// let bytes = [2; 97];
  /// let proof = AdaptorProof::from_slice(&bytes).expect("Fail");
  /// ```
  pub fn from_slice(data: &[u8]) -> Result<AdaptorProof, CfdError> {
    AdaptorProof::from_vec(data.to_vec())
  }

  /// Generate from vector.
  ///
  /// # Arguments
  /// * `data` - A proof vector
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::AdaptorProof;
  /// let bytes = [2; 97];
  /// let proof = AdaptorProof::from_vec(bytes.to_vec()).expect("Fail");
  /// ```
  pub fn from_vec(data: Vec<u8>) -> Result<AdaptorProof, CfdError> {
    match data.len() {
      ADAPTOR_PROOF_SIZE => Ok(AdaptorProof { data }),
      _ => Err(CfdError::IllegalArgument(
        "invalid pubkey format.".to_string(),
      )),
    }
  }

  #[inline]
  pub fn to_slice(&self) -> &[u8] {
    &self.data
  }

  #[inline]
  pub fn to_hex(&self) -> String {
    hex_from_bytes(&self.data)
  }

  #[inline]
  pub fn to_str(&self) -> String {
    self.to_hex()
  }
}

impl fmt::Display for AdaptorProof {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    let s = hex::encode(&self.data);
    write!(f, "{}", s)
  }
}

impl FromStr for AdaptorProof {
  type Err = CfdError;
  fn from_str(text: &str) -> Result<AdaptorProof, CfdError> {
    match byte_from_hex(text) {
      Ok(byte_array) => AdaptorProof::from_vec(byte_array),
      Err(e) => Err(e),
    }
  }
}

impl Default for AdaptorProof {
  fn default() -> AdaptorProof {
    AdaptorProof { data: vec![] }
  }
}

pub struct AdaptorPair {
  pub signature: AdaptorSignature,
  pub proof: AdaptorProof,
}

/// A container that stores ecdsAn adaptor API.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct EcdsaAdaptorUtil {}

impl EcdsaAdaptorUtil {
  pub fn new() -> EcdsaAdaptorUtil {
    EcdsaAdaptorUtil::default()
  }

  /// Sign by ecdsa-adaptor.
  ///
  /// # Arguments
  /// * `msg` - A 32-byte message bytes
  /// * `secret_key` - A secret key
  /// * `adaptor` - An adaptor pubkey
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{EcdsaAdaptorUtil, ByteData, Pubkey, Privkey};
  /// use std::str::FromStr;
  /// let msg = ByteData::from_str("024bdd11f2144e825db05759bdd9041367a420fad14b665fd08af5b42056e5e2").expect("Fail");
  /// let adaptor = Pubkey::from_str("038d48057fc4ce150482114d43201b333bf3706f3cd527e8767ceb4b443ab5d349").expect("Fail");
  /// let sk = Privkey::from_str("90ac0d5dc0a1a9ab352afb02005a5cc6c4df0da61d8149d729ff50db9b5a5215").expect("Fail");
  /// let obj = EcdsaAdaptorUtil::new();
  /// let pair = obj.sign(&msg, &sk, &adaptor).expect("Fail");
  /// ```
  pub fn sign(
    &self,
    msg: &ByteData,
    secret_key: &Privkey,
    adaptor: &Pubkey,
  ) -> Result<AdaptorPair, CfdError> {
    let msg_hex = alloc_c_string(&msg.to_hex())?;
    let sk_hex = alloc_c_string(&secret_key.to_hex())?;
    let adaptor_hex = alloc_c_string(&adaptor.to_hex())?;
    let handle = ErrorHandle::new()?;
    let mut signature: *mut c_char = ptr::null_mut();
    let mut proof: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdSignEcdsaAdaptor(
        handle.as_handle(),
        msg_hex.as_ptr(),
        sk_hex.as_ptr(),
        adaptor_hex.as_ptr(),
        &mut signature,
        &mut proof,
      )
    };
    let result = match error_code {
      0 => {
        let str_list = unsafe { collect_multi_cstring_and_free(&[signature, proof]) }?;
        let sig = AdaptorSignature::from_str(&str_list[0])?;
        let proof_obj = AdaptorProof::from_str(&str_list[1])?;
        Ok(AdaptorPair {
          signature: sig,
          proof: proof_obj,
        })
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  /// "Decrypt" an adaptor signature using the provided secret.
  ///
  /// # Arguments
  /// * `adaptor_signature` - An adaptor signature
  /// * `adaptor_secret` - An adaptor secret key
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{EcdsaAdaptorUtil, AdaptorSignature, AdaptorProof, Privkey};
  /// use std::str::FromStr;
  /// let adaptor_sig = AdaptorSignature::from_str("00cbe0859638c3600ea1872ed7a55b8182a251969f59d7d2da6bd4afedf25f5021a49956234cbbbbede8ca72e0113319c84921bf1224897a6abd89dc96b9c5b208").expect("Fail");
  /// let secret = Privkey::from_str("475697a71a74ff3f2a8f150534e9b67d4b0b6561fab86fcaa51f8c9d6c9db8c6").expect("Fail");
  /// let obj = EcdsaAdaptorUtil::new();
  /// let sig = obj.adapt(&adaptor_sig, &secret).expect("Fail");
  /// ```
  pub fn adapt(
    &self,
    adaptor_signature: &AdaptorSignature,
    adaptor_secret: &Privkey,
  ) -> Result<ByteData, CfdError> {
    let sig_hex = alloc_c_string(&adaptor_signature.to_hex())?;
    let sk_hex = alloc_c_string(&adaptor_secret.to_hex())?;
    let handle = ErrorHandle::new()?;
    let mut signature: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdAdaptEcdsaAdaptor(
        handle.as_handle(),
        sig_hex.as_ptr(),
        sk_hex.as_ptr(),
        &mut signature,
      )
    };
    let result = match error_code {
      0 => {
        let sig = unsafe { collect_cstring_and_free(signature) }?;
        ByteData::from_str(&sig)
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  /// Extract an adaptor secret from an ECDSA signature for a given adaptor signature.
  ///
  /// # Arguments
  /// * `adaptor_signature` - An adaptor signature
  /// * `signature` - A ecdsa signature
  /// * `adaptor` - An adaptor pubkey
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{EcdsaAdaptorUtil, AdaptorSignature, ByteData, Pubkey};
  /// use std::str::FromStr;
  /// let adaptor_sig = AdaptorSignature::from_str("00cbe0859638c3600ea1872ed7a55b8182a251969f59d7d2da6bd4afedf25f5021a49956234cbbbbede8ca72e0113319c84921bf1224897a6abd89dc96b9c5b208").expect("Fail");
  /// let sig = ByteData::from_str("099c91aa1fe7f25c41085c1d3c9e73fe04a9d24dac3f9c2172d6198628e57f474d13456e98d8989043fd4674302ce90c432e2f8bb0269f02c72aafec60b72de1").expect("Fail");
  /// let adaptor = Pubkey::from_str("038d48057fc4ce150482114d43201b333bf3706f3cd527e8767ceb4b443ab5d349").expect("Fail");
  /// let obj = EcdsaAdaptorUtil::new();
  /// let secret = obj.extract_secret(&adaptor_sig, &sig, &adaptor).expect("Fail");
  /// ```
  pub fn extract_secret(
    &self,
    adaptor_signature: &AdaptorSignature,
    signature: &ByteData,
    adaptor: &Pubkey,
  ) -> Result<Privkey, CfdError> {
    let adaptor_sig_hex = alloc_c_string(&adaptor_signature.to_hex())?;
    let sig_hex = alloc_c_string(&signature.to_hex())?;
    let adaptor_hex = alloc_c_string(&adaptor.to_hex())?;
    let handle = ErrorHandle::new()?;
    let mut secret: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdExtractEcdsaAdaptorSecret(
        handle.as_handle(),
        adaptor_sig_hex.as_ptr(),
        sig_hex.as_ptr(),
        adaptor_hex.as_ptr(),
        &mut secret,
      )
    };
    let result = match error_code {
      0 => {
        let secret_key = unsafe { collect_cstring_and_free(secret) }?;
        Privkey::from_str(&secret_key)
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  /// Verify adaptor signature.
  ///
  /// # Arguments
  /// * `adaptor_signature` - An adaptor signature
  /// * `proof` - An adaptor proof
  /// * `adaptor` - An adaptor pubkey
  /// * `msg` - A 32-byte message bytes
  /// * `pubkey` - A signed pubkey
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{EcdsaAdaptorUtil, AdaptorSignature, AdaptorProof, ByteData, Pubkey};
  /// use std::str::FromStr;
  /// let adaptor_sig = AdaptorSignature::from_str("00cbe0859638c3600ea1872ed7a55b8182a251969f59d7d2da6bd4afedf25f5021a49956234cbbbbede8ca72e0113319c84921bf1224897a6abd89dc96b9c5b208").expect("Fail");
  /// let adaptor_proof = AdaptorProof::from_str("00b02472be1ba09f5675488e841a10878b38c798ca63eff3650c8e311e3e2ebe2e3b6fee5654580a91cc5149a71bf25bcbeae63dea3ac5ad157a0ab7373c3011d0fc2592a07f719c5fc1323f935569ecd010db62f045e965cc1d564eb42cce8d6d").expect("Fail");
  /// let adaptor = Pubkey::from_str("038d48057fc4ce150482114d43201b333bf3706f3cd527e8767ceb4b443ab5d349").expect("Fail");
  /// let msg = ByteData::from_str("024bdd11f2144e825db05759bdd9041367a420fad14b665fd08af5b42056e5e2").expect("Fail");
  /// let pubkey = Pubkey::from_str("03490cec9a53cd8f2f664aea61922f26ee920c42d2489778bb7c9d9ece44d149a7").expect("Fail");
  /// let obj = EcdsaAdaptorUtil::new();
  /// let is_verify = obj.verify(&adaptor_sig, &adaptor_proof, &adaptor, &msg, &pubkey).expect("Fail");
  /// ```
  pub fn verify(
    &self,
    adaptor_signature: &AdaptorSignature,
    proof: &AdaptorProof,
    adaptor: &Pubkey,
    msg: &ByteData,
    pubkey: &Pubkey,
  ) -> Result<bool, CfdError> {
    let sig_hex = alloc_c_string(&adaptor_signature.to_hex())?;
    let proof_hex = alloc_c_string(&proof.to_hex())?;
    let adaptor_hex = alloc_c_string(&adaptor.to_hex())?;
    let msg_hex = alloc_c_string(&msg.to_hex())?;
    let pubkey_hex = alloc_c_string(&pubkey.to_hex())?;
    let handle = ErrorHandle::new()?;
    let error_code = unsafe {
      CfdVerifyEcdsaAdaptor(
        handle.as_handle(),
        sig_hex.as_ptr(),
        proof_hex.as_ptr(),
        adaptor_hex.as_ptr(),
        msg_hex.as_ptr(),
        pubkey_hex.as_ptr(),
      )
    };
    let result = match error_code {
      0 => Ok(true),
      7 => Ok(false), // SignVerification
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }
}

impl Default for EcdsaAdaptorUtil {
  fn default() -> EcdsaAdaptorUtil {
    EcdsaAdaptorUtil {}
  }
}

/// A container that stores a schnorr signature.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SchnorrSignature {
  data: Vec<u8>,
  nonce: SchnorrNonce,
  key: Privkey,
}

impl SchnorrSignature {
  /// Generate from slice.
  ///
  /// # Arguments
  /// * `data` - A signature bytes
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::SchnorrSignature;
  /// let bytes = [2; 64];
  /// let sig = SchnorrSignature::from_slice(&bytes).expect("Fail");
  /// ```
  pub fn from_slice(data: &[u8]) -> Result<SchnorrSignature, CfdError> {
    SchnorrSignature::from_vec(data.to_vec())
  }

  /// Generate from vector.
  ///
  /// # Arguments
  /// * `data` - A signature vector
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::SchnorrSignature;
  /// let bytes = [2; 64];
  /// let sig = SchnorrSignature::from_vec(bytes.to_vec()).expect("Fail");
  /// ```
  pub fn from_vec(data: Vec<u8>) -> Result<SchnorrSignature, CfdError> {
    if data.len() != SCHNORR_SIGNATURE_SIZE {
      return Err(CfdError::IllegalArgument(
        "invalid signature format.".to_string(),
      ));
    }
    let signature_hex = alloc_c_string(&hex_from_bytes(&data))?;
    let handle = ErrorHandle::new()?;
    let mut nonce_hex: *mut c_char = ptr::null_mut();
    let mut key_hex: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdSplitSchnorrSignature(
        handle.as_handle(),
        signature_hex.as_ptr(),
        &mut nonce_hex,
        &mut key_hex,
      )
    };
    let result = match error_code {
      0 => {
        let str_list = unsafe { collect_multi_cstring_and_free(&[nonce_hex, key_hex]) }?;
        let nonce = SchnorrNonce::from_str(&str_list[0])?;
        let key = Privkey::from_str(&str_list[1])?;
        Ok(SchnorrSignature { data, nonce, key })
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  #[inline]
  pub fn to_slice(&self) -> &[u8] {
    &self.data
  }

  #[inline]
  pub fn to_hex(&self) -> String {
    hex_from_bytes(&self.data)
  }

  #[inline]
  pub fn to_str(&self) -> String {
    self.to_hex()
  }

  #[inline]
  pub fn as_nonce(&self) -> &SchnorrNonce {
    &self.nonce
  }

  #[inline]
  pub fn as_key(&self) -> &Privkey {
    &self.key
  }
}

impl fmt::Display for SchnorrSignature {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    let s = hex::encode(&self.data);
    write!(f, "{}", s)
  }
}

impl FromStr for SchnorrSignature {
  type Err = CfdError;
  fn from_str(text: &str) -> Result<SchnorrSignature, CfdError> {
    match byte_from_hex(text) {
      Ok(byte_array) => SchnorrSignature::from_vec(byte_array),
      Err(e) => Err(e),
    }
  }
}

/// A container that stores a schnorr nonce.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SchnorrNonce {
  data: [u8; SCHNORR_NONCE_SIZE],
}

impl SchnorrNonce {
  fn from_bytes(data: &[u8]) -> SchnorrNonce {
    let mut nonce = SchnorrNonce {
      data: [0; SCHNORR_NONCE_SIZE],
    };
    nonce.data = copy_array_32byte(&data);
    nonce
  }

  /// Generate from slice.
  ///
  /// # Arguments
  /// * `data` - A nonce bytes
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::SchnorrNonce;
  /// let bytes = [1; 32];
  /// let nonce = SchnorrNonce::from_slice(&bytes).expect("Fail");
  /// ```
  pub fn from_slice(data: &[u8]) -> Result<SchnorrNonce, CfdError> {
    match data.len() {
      SCHNORR_NONCE_SIZE => Ok(SchnorrNonce::from_bytes(data)),
      _ => Err(CfdError::IllegalArgument("invalid nonce.".to_string())),
    }
  }

  /// Generate from vector.
  ///
  /// # Arguments
  /// * `data` - A nonce bytes
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::SchnorrNonce;
  /// let bytes = vec![1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1];
  /// let nonce = SchnorrNonce::from_vec(bytes).expect("Fail");
  /// ```
  pub fn from_vec(data: Vec<u8>) -> Result<SchnorrNonce, CfdError> {
    SchnorrNonce::from_slice(&data)
  }

  #[inline]
  pub fn to_slice(&self) -> &[u8] {
    &self.data
  }

  #[inline]
  pub fn to_hex(&self) -> String {
    hex_from_bytes(&self.data)
  }

  #[inline]
  pub fn to_str(&self) -> String {
    self.to_hex()
  }

  pub fn as_key(&self) -> Result<Privkey, CfdError> {
    Privkey::from_slice(&self.data)
  }
}

impl fmt::Display for SchnorrNonce {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    let s = hex::encode(&self.data);
    write!(f, "{}", s)
  }
}

impl FromStr for SchnorrNonce {
  type Err = CfdError;
  fn from_str(text: &str) -> Result<SchnorrNonce, CfdError> {
    match byte_from_hex(text) {
      Ok(byte_array) => SchnorrNonce::from_vec(byte_array),
      Err(e) => Err(e),
    }
  }
}

impl Default for SchnorrNonce {
  fn default() -> SchnorrNonce {
    SchnorrNonce {
      data: [0; SCHNORR_NONCE_SIZE],
    }
  }
}

/// A container that stores schnorr API.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SchnorrUtil {}

impl SchnorrUtil {
  pub fn new() -> SchnorrUtil {
    SchnorrUtil::default()
  }

  /// Sign by schnorr.
  ///
  /// # Arguments
  /// * `msg` - A 32-byte message bytes
  /// * `secret_key` - A secret key
  /// * `aux_rand` - A 32-byte random bytes
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{SchnorrUtil, ByteData, Privkey};
  /// use std::str::FromStr;
  /// let msg = ByteData::from_str("e48441762fb75010b2aa31a512b62b4148aa3fb08eb0765d76b252559064a614").expect("Fail");
  /// let sk = Privkey::from_str("688c77bc2d5aaff5491cf309d4753b732135470d05b7b2cd21add0744fe97bef").expect("Fail");
  /// let aux_rand = ByteData::from_str("02cce08e913f22a36c5648d6405a2c7c50106e7aa2f1649e381c7f09d16b80ab").expect("Fail");
  /// let obj = SchnorrUtil::new();
  /// let sig = obj.sign(&msg, &sk, &aux_rand).expect("Fail");
  /// ```
  pub fn sign(
    &self,
    msg: &ByteData,
    secret_key: &Privkey,
    aux_rand: &ByteData,
  ) -> Result<SchnorrSignature, CfdError> {
    let msg_hex = alloc_c_string(&msg.to_hex())?;
    let sk_hex = alloc_c_string(&secret_key.to_hex())?;
    let rand_hex = alloc_c_string(&aux_rand.to_hex())?;
    let handle = ErrorHandle::new()?;
    let mut signature: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdSignSchnorr(
        handle.as_handle(),
        msg_hex.as_ptr(),
        sk_hex.as_ptr(),
        rand_hex.as_ptr(),
        &mut signature,
      )
    };
    let result = match error_code {
      0 => {
        let sig = unsafe { collect_cstring_and_free(signature) }?;
        SchnorrSignature::from_str(&sig)
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  /// Sign by schnorr with nonce.
  ///
  /// # Arguments
  /// * `msg` - A 32-byte message bytes
  /// * `secret_key` - A secret key
  /// * `nonce` - A 32-byte nonce bytes
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{SchnorrUtil, ByteData, Privkey};
  /// use std::str::FromStr;
  /// let msg = ByteData::from_str("e48441762fb75010b2aa31a512b62b4148aa3fb08eb0765d76b252559064a614").expect("Fail");
  /// let sk = Privkey::from_str("688c77bc2d5aaff5491cf309d4753b732135470d05b7b2cd21add0744fe97bef").expect("Fail");
  /// let nonce = Privkey::from_str("8c8ca771d3c25eb38de7401818eeda281ac5446f5c1396148f8d9d67592440fe").expect("Fail");
  /// let obj = SchnorrUtil::new();
  /// let sig = obj.sign_with_nonce(&msg, &sk, &nonce).expect("Fail");
  /// ```
  pub fn sign_with_nonce(
    &self,
    msg: &ByteData,
    secret_key: &Privkey,
    nonce: &Privkey,
  ) -> Result<SchnorrSignature, CfdError> {
    let msg_hex = alloc_c_string(&msg.to_hex())?;
    let sk_hex = alloc_c_string(&secret_key.to_hex())?;
    let nonce_hex = alloc_c_string(&nonce.to_hex())?;
    let handle = ErrorHandle::new()?;
    let mut signature: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdSignSchnorrWithNonce(
        handle.as_handle(),
        msg_hex.as_ptr(),
        sk_hex.as_ptr(),
        nonce_hex.as_ptr(),
        &mut signature,
      )
    };
    let result = match error_code {
      0 => {
        let sig = unsafe { collect_cstring_and_free(signature) }?;
        SchnorrSignature::from_str(&sig)
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  /// Compute sig-point.
  ///
  /// # Arguments
  /// * `msg` - A 32-byte message bytes
  /// * `nonce` - A schnorr nonce
  /// * `pubkey` - A public key
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{SchnorrUtil, SchnorrNonce, ByteData, Pubkey};
  /// use std::str::FromStr;
  /// let msg = ByteData::from_str("e48441762fb75010b2aa31a512b62b4148aa3fb08eb0765d76b252559064a614").expect("Fail");
  /// let nonce = SchnorrNonce::from_str("f14d7e54ff58c5d019ce9986be4a0e8b7d643bd08ef2cdf1099e1a457865b547").expect("Fail");
  /// let pubkey = Pubkey::from_str("02b33cc9edc096d0a83416964bd3c6247b8fecd256e4efa7870d2c854bdeb33390").expect("Fail");
  /// let obj = SchnorrUtil::new();
  /// let point = obj.compute_sig_point(&msg, &nonce, &pubkey).expect("Fail");
  /// ```
  pub fn compute_sig_point(
    &self,
    msg: &ByteData,
    nonce: &SchnorrNonce,
    pubkey: &Pubkey,
  ) -> Result<Pubkey, CfdError> {
    let msg_hex = alloc_c_string(&msg.to_hex())?;
    let nonce_hex = alloc_c_string(&nonce.to_hex())?;
    let pubkey_hex = alloc_c_string(&pubkey.to_hex())?;
    let handle = ErrorHandle::new()?;
    let mut sig_point: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdComputeSchnorrSigPoint(
        handle.as_handle(),
        msg_hex.as_ptr(),
        nonce_hex.as_ptr(),
        pubkey_hex.as_ptr(),
        &mut sig_point,
      )
    };
    let result = match error_code {
      0 => {
        let point = unsafe { collect_cstring_and_free(sig_point) }?;
        Pubkey::from_str(&point)
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  /// Verify schnorr signature.
  ///
  /// # Arguments
  /// * `signature` - A schnorr signature
  /// * `msg` - A 32-byte message bytes
  /// * `pubkey` - A public key
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{SchnorrUtil, SchnorrSignature, ByteData, Pubkey};
  /// use std::str::FromStr;
  /// let sig = SchnorrSignature::from_str("f14d7e54ff58c5d019ce9986be4a0e8b7d643bd08ef2cdf1099e1a457865b5477c988c51634a8dc955950a58ff5dc8c506ddb796121e6675946312680c26cf33").expect("Fail");
  /// let msg = ByteData::from_str("e48441762fb75010b2aa31a512b62b4148aa3fb08eb0765d76b252559064a614").expect("Fail");
  /// let pubkey = Pubkey::from_str("02b33cc9edc096d0a83416964bd3c6247b8fecd256e4efa7870d2c854bdeb33390").expect("Fail");
  /// let obj = SchnorrUtil::new();
  /// let is_verify = obj.verify(&sig, &msg, &pubkey).expect("Fail");
  /// ```
  pub fn verify(
    &self,
    signature: &SchnorrSignature,
    msg: &ByteData,
    pubkey: &Pubkey,
  ) -> Result<bool, CfdError> {
    let sig_hex = alloc_c_string(&signature.to_hex())?;
    let msg_hex = alloc_c_string(&msg.to_hex())?;
    let pubkey_hex = alloc_c_string(&pubkey.to_hex())?;
    let handle = ErrorHandle::new()?;
    let error_code = unsafe {
      CfdVerifySchnorr(
        handle.as_handle(),
        sig_hex.as_ptr(),
        msg_hex.as_ptr(),
        pubkey_hex.as_ptr(),
      )
    };
    let result = match error_code {
      0 => Ok(true),
      7 => Ok(false), // SignVerification
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }
}

impl Default for SchnorrUtil {
  fn default() -> SchnorrUtil {
    SchnorrUtil {}
  }
}
