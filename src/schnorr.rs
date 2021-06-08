extern crate cfd_sys;
extern crate libc;

use self::libc::c_char;
use crate::common::{
  alloc_c_string, byte_from_hex, collect_cstring_and_free, collect_multi_cstring_and_free,
  copy_array_32byte, hex_from_bytes, ByteData, CfdError, ErrorHandle,
};
use crate::key::{Privkey, Pubkey, SigHashType, SignParameter};
use std::fmt;
use std::ptr;
use std::result::Result::{Err, Ok};
use std::str::FromStr;

use self::cfd_sys::{
  CfdCheckTweakAddFromSchnorrPubkey, CfdComputeSchnorrSigPoint, CfdDecryptEcdsaAdaptor,
  CfdEncryptEcdsaAdaptor, CfdGetSchnorrPubkeyFromPrivkey, CfdGetSchnorrPubkeyFromPubkey,
  CfdRecoverEcdsaAdaptor, CfdSchnorrKeyPairTweakAdd, CfdSchnorrPubkeyTweakAdd, CfdSignSchnorr,
  CfdSignSchnorrWithNonce, CfdSplitSchnorrSignature, CfdVerifyEcdsaAdaptor, CfdVerifySchnorr,
};

/// adaptor signature size.
pub const ADAPTOR_SIGNATURE_SIZE: usize = 162;
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
  /// Encrypt by ecdsa-adaptor.
  ///
  /// # Arguments
  /// * `msg` - A 32-byte message bytes
  /// * `secret_key` - A secret key
  /// * `encryption_key` - An encryption key
  pub fn encrypt(
    msg: &ByteData,
    secret_key: &Privkey,
    encryption_key: &Pubkey,
  ) -> Result<AdaptorSignature, CfdError> {
    let msg_hex = alloc_c_string(&msg.to_hex())?;
    let sk_hex = alloc_c_string(&secret_key.to_hex())?;
    let adaptor_hex = alloc_c_string(&encryption_key.to_hex())?;
    let mut handle = ErrorHandle::new()?;
    let mut signature: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdEncryptEcdsaAdaptor(
        handle.as_handle(),
        msg_hex.as_ptr(),
        sk_hex.as_ptr(),
        adaptor_hex.as_ptr(),
        &mut signature,
      )
    };
    let result = match error_code {
      0 => {
        let sig_str = unsafe { collect_cstring_and_free(signature) }?;
        Ok(AdaptorSignature::from_str(&sig_str)?)
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  /// Generate from slice.
  ///
  /// # Arguments
  /// * `key` - A public key bytes
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::AdaptorSignature;
  /// let bytes = [2; 162];
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
  /// let bytes = [2; 162];
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

  /// "Decrypt" an adaptor signature using the provided secret.
  ///
  /// # Arguments
  /// * `adaptor_secret` - An adaptor secret key
  pub fn decrypt(&self, adaptor_secret: &Privkey) -> Result<ByteData, CfdError> {
    let sig_hex = alloc_c_string(&hex_from_bytes(&self.data))?;
    let sk_hex = alloc_c_string(&adaptor_secret.to_hex())?;
    let mut handle = ErrorHandle::new()?;
    let mut signature: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdDecryptEcdsaAdaptor(
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
  /// * `signature` - A ecdsa signature
  /// * `encryption_key` - An encryption key
  pub fn recover(
    &self,
    signature: &ByteData,
    encryption_key: &Pubkey,
  ) -> Result<Privkey, CfdError> {
    let adaptor_sig_hex = alloc_c_string(&hex_from_bytes(&self.data))?;
    let sig_hex = alloc_c_string(&signature.to_hex())?;
    let adaptor_hex = alloc_c_string(&encryption_key.to_hex())?;
    let mut handle = ErrorHandle::new()?;
    let mut secret: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdRecoverEcdsaAdaptor(
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
  /// * `msg` - A 32-byte message bytes
  /// * `pubkey` - A signed pubkey
  /// * `encryption_key` - An encryption key
  pub fn verify(
    &self,
    msg: &ByteData,
    pubkey: &Pubkey,
    encryption_key: &Pubkey,
  ) -> Result<bool, CfdError> {
    let sig_hex = alloc_c_string(&hex_from_bytes(&self.data))?;
    let adaptor_hex = alloc_c_string(&encryption_key.to_hex())?;
    let msg_hex = alloc_c_string(&msg.to_hex())?;
    let pubkey_hex = alloc_c_string(&pubkey.to_hex())?;
    let mut handle = ErrorHandle::new()?;
    let error_code = unsafe {
      CfdVerifyEcdsaAdaptor(
        handle.as_handle(),
        sig_hex.as_ptr(),
        msg_hex.as_ptr(),
        pubkey_hex.as_ptr(),
        adaptor_hex.as_ptr(),
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

/// A container that stores a schnorr signature.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SchnorrSignature {
  data: Vec<u8>,
  nonce: SchnorrPubkey,
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
    let mut handle = ErrorHandle::new()?;
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
        let nonce = SchnorrPubkey::from_str(&str_list[0])?;
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
  pub fn as_nonce(&self) -> &SchnorrPubkey {
    &self.nonce
  }

  #[inline]
  pub fn as_key(&self) -> &Privkey {
    &self.key
  }

  /// Get sign parameter.
  ///
  /// # Arguments
  /// * `sighash_type` - A signature hash type.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{SchnorrSignature, SigHashType};
  /// let bytes = [2; 64];
  /// let sig = SchnorrSignature::from_vec(bytes.to_vec()).expect("Fail");
  /// let sign_param = sig.get_sign_parameter(&SigHashType::All);
  /// ```
  pub fn get_sign_parameter(&self, sighash_type: &SigHashType) -> SignParameter {
    SignParameter::from_slice(&self.data).set_signature_hash(sighash_type)
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
pub struct SchnorrPubkey {
  data: [u8; SCHNORR_NONCE_SIZE],
}

impl SchnorrPubkey {
  fn from_bytes(data: &[u8]) -> SchnorrPubkey {
    SchnorrPubkey {
      data: copy_array_32byte(&data),
    }
  }

  /// Generate from slice.
  ///
  /// # Arguments
  /// * `data` - A nonce bytes
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::SchnorrPubkey;
  /// let bytes = [1; 32];
  /// let pubkey = SchnorrPubkey::from_slice(&bytes).expect("Fail");
  /// ```
  pub fn from_slice(data: &[u8]) -> Result<SchnorrPubkey, CfdError> {
    match data.len() {
      SCHNORR_NONCE_SIZE => Ok(SchnorrPubkey::from_bytes(data)),
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
  /// use cfd_rust::SchnorrPubkey;
  /// let bytes = vec![1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1];
  /// let pubkey = SchnorrPubkey::from_vec(bytes).expect("Fail");
  /// ```
  pub fn from_vec(data: Vec<u8>) -> Result<SchnorrPubkey, CfdError> {
    SchnorrPubkey::from_slice(&data)
  }

  /// Generate from privkey.
  ///
  /// # Arguments
  /// * `key` - A private key.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{SchnorrPubkey, Privkey};
  /// use std::str::FromStr;
  /// let key = Privkey::from_str("475697a71a74ff3f2a8f150534e9b67d4b0b6561fab86fcaa51f8c9d6c9db8c6").expect("Fail");
  /// let pubkey_ret = SchnorrPubkey::from_privkey(&key).expect("Fail");
  /// let (pubkey, parity) = pubkey_ret;
  /// ```
  pub fn from_privkey(key: &Privkey) -> Result<(SchnorrPubkey, bool), CfdError> {
    let key_hex = alloc_c_string(&key.to_hex())?;
    let mut handle = ErrorHandle::new()?;
    let mut pubkey_hex: *mut c_char = ptr::null_mut();
    let mut parity = false;
    let error_code = unsafe {
      CfdGetSchnorrPubkeyFromPrivkey(
        handle.as_handle(),
        key_hex.as_ptr(),
        &mut pubkey_hex,
        &mut parity,
      )
    };
    let result = match error_code {
      0 => {
        let pubkey = unsafe { collect_cstring_and_free(pubkey_hex) }?;
        let pubkey_obj = SchnorrPubkey::from_str(&pubkey)?;
        Ok((pubkey_obj, parity))
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  /// Generate from pubkey.
  ///
  /// # Arguments
  /// * `key` - A public key.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{SchnorrPubkey, Pubkey};
  /// use std::str::FromStr;
  /// let key = Pubkey::from_str("03b33cc9edc096d0a83416964bd3c6247b8fecd256e4efa7870d2c854bdeb33390").expect("Fail");
  /// let pubkey_ret = SchnorrPubkey::from_pubkey(&key).expect("Fail");
  /// let (pubkey, parity) = pubkey_ret;
  /// ```
  pub fn from_pubkey(key: &Pubkey) -> Result<(SchnorrPubkey, bool), CfdError> {
    let key_hex = alloc_c_string(&key.to_hex())?;
    let mut handle = ErrorHandle::new()?;
    let mut pubkey_hex: *mut c_char = ptr::null_mut();
    let mut parity = false;
    let error_code = unsafe {
      CfdGetSchnorrPubkeyFromPubkey(
        handle.as_handle(),
        key_hex.as_ptr(),
        &mut pubkey_hex,
        &mut parity,
      )
    };
    let result = match error_code {
      0 => {
        let pubkey = unsafe { collect_cstring_and_free(pubkey_hex) }?;
        let pubkey_obj = SchnorrPubkey::from_str(&pubkey)?;
        Ok((pubkey_obj, parity))
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  /// Generate tweaked key pair from privkey.
  ///
  /// # Arguments
  /// * `key` - A private key.
  /// * `data` - A tweaked 32 byte buffer.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{SchnorrPubkey, Privkey, ByteData};
  /// use std::str::FromStr;
  /// let key = Privkey::from_str("475697a71a74ff3f2a8f150534e9b67d4b0b6561fab86fcaa51f8c9d6c9db8c6").expect("Fail");
  /// let tweak = ByteData::from_str("e48441762fb75010b2aa31a512b62b4148aa3fb08eb0765d76b252559064a614").expect("Fail");
  /// let pubkey_ret = SchnorrPubkey::get_tweak_add_from_privkey(&key, tweak.to_slice()).expect("Fail");
  /// let (pubkey, parity, privkey) = pubkey_ret;
  /// ```
  pub fn get_tweak_add_from_privkey(
    key: &Privkey,
    data: &[u8],
  ) -> Result<(SchnorrPubkey, bool, Privkey), CfdError> {
    let key_hex = alloc_c_string(&key.to_hex())?;
    let tweak_hex = alloc_c_string(&hex_from_bytes(data))?;
    let mut handle = ErrorHandle::new()?;
    let mut pubkey_hex: *mut c_char = ptr::null_mut();
    let mut privkey_hex: *mut c_char = ptr::null_mut();
    let mut parity = false;
    let error_code = unsafe {
      CfdSchnorrKeyPairTweakAdd(
        handle.as_handle(),
        key_hex.as_ptr(),
        tweak_hex.as_ptr(),
        &mut pubkey_hex,
        &mut parity,
        &mut privkey_hex,
      )
    };
    let result = match error_code {
      0 => {
        let str_list = unsafe { collect_multi_cstring_and_free(&[pubkey_hex, privkey_hex]) }?;
        let pubkey_obj = SchnorrPubkey::from_str(&str_list[0])?;
        let privkey_obj = Privkey::from_str(&str_list[1])?;
        Ok((pubkey_obj, parity, privkey_obj))
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

  pub fn as_key(&self) -> Result<Privkey, CfdError> {
    Privkey::from_slice(&self.data)
  }

  /// Generate tweaked schnorr pubkey.
  ///
  /// # Arguments
  /// * `data` - A tweaked 32 byte buffer.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{SchnorrPubkey, ByteData};
  /// use std::str::FromStr;
  /// let key = SchnorrPubkey::from_str("b33cc9edc096d0a83416964bd3c6247b8fecd256e4efa7870d2c854bdeb33390").expect("Fail");
  /// let tweak = ByteData::from_str("e48441762fb75010b2aa31a512b62b4148aa3fb08eb0765d76b252559064a614").expect("Fail");
  /// let pubkey_ret = key.tweak_add(tweak.to_slice()).expect("Fail");
  /// let (pubkey, parity) = pubkey_ret;
  /// ```
  pub fn tweak_add(&self, data: &[u8]) -> Result<(SchnorrPubkey, bool), CfdError> {
    let key_hex = alloc_c_string(&self.to_hex())?;
    let tweak_hex = alloc_c_string(&hex_from_bytes(data))?;
    let mut handle = ErrorHandle::new()?;
    let mut pubkey_hex: *mut c_char = ptr::null_mut();
    let mut parity = false;
    let error_code = unsafe {
      CfdSchnorrPubkeyTweakAdd(
        handle.as_handle(),
        key_hex.as_ptr(),
        tweak_hex.as_ptr(),
        &mut pubkey_hex,
        &mut parity,
      )
    };
    let result = match error_code {
      0 => {
        let pubkey = unsafe { collect_cstring_and_free(pubkey_hex) }?;
        let pubkey_obj = SchnorrPubkey::from_str(&pubkey)?;
        Ok((pubkey_obj, parity))
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  /// Generate tweaked schnorr pubkey.
  ///
  /// # Arguments
  /// * `data` - A tweaked 32 byte buffer.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{SchnorrPubkey, ByteData};
  /// use std::str::FromStr;
  /// let key = SchnorrPubkey::from_str("b33cc9edc096d0a83416964bd3c6247b8fecd256e4efa7870d2c854bdeb33390").expect("Fail");
  /// let tweak = ByteData::from_str("e48441762fb75010b2aa31a512b62b4148aa3fb08eb0765d76b252559064a614").expect("Fail");
  /// let tweaked_key = SchnorrPubkey::from_str("1fc8e882e34cc7942a15f39ffaebcbdf58a19239bcb17b7f5aa88e0eb808f906").expect("Fail");
  /// let is_valid = tweaked_key.is_tweaked(true, &key, tweak.to_slice()).expect("Fail");
  /// ```
  pub fn is_tweaked(
    &self,
    parity: bool,
    base_pubkey: &SchnorrPubkey,
    data: &[u8],
  ) -> Result<bool, CfdError> {
    let key_hex = alloc_c_string(&self.to_hex())?;
    let base_key_hex = alloc_c_string(&base_pubkey.to_hex())?;
    let tweak_hex = alloc_c_string(&hex_from_bytes(data))?;
    let mut handle = ErrorHandle::new()?;
    let error_code = unsafe {
      CfdCheckTweakAddFromSchnorrPubkey(
        handle.as_handle(),
        key_hex.as_ptr(),
        parity,
        base_key_hex.as_ptr(),
        tweak_hex.as_ptr(),
      )
    };
    let result = match error_code {
      0 => Ok(true),
      7 => Ok(false),
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  /// Check valid data.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{SchnorrPubkey};
  /// use std::str::FromStr;
  /// let key = SchnorrPubkey::from_str("b33cc9edc096d0a83416964bd3c6247b8fecd256e4efa7870d2c854bdeb33390").expect("Fail");
  /// let is_valid = key.valid();
  /// assert_eq!(true, is_valid);
  /// assert_eq!(false, SchnorrPubkey::default().valid());
  /// ```
  #[inline]
  pub fn valid(&self) -> bool {
    let null_value = SchnorrPubkey::default();
    null_value.data != self.data
  }
}

impl fmt::Display for SchnorrPubkey {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    let s = hex::encode(&self.data);
    write!(f, "{}", s)
  }
}

impl FromStr for SchnorrPubkey {
  type Err = CfdError;
  fn from_str(text: &str) -> Result<SchnorrPubkey, CfdError> {
    match byte_from_hex(text) {
      Ok(byte_array) => SchnorrPubkey::from_vec(byte_array),
      Err(e) => Err(e),
    }
  }
}

impl Default for SchnorrPubkey {
  fn default() -> SchnorrPubkey {
    SchnorrPubkey {
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
    let mut handle = ErrorHandle::new()?;
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
    let mut handle = ErrorHandle::new()?;
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
  /// use cfd_rust::{SchnorrUtil, SchnorrPubkey, ByteData};
  /// use std::str::FromStr;
  /// let msg = ByteData::from_str("e48441762fb75010b2aa31a512b62b4148aa3fb08eb0765d76b252559064a614").expect("Fail");
  /// let nonce = SchnorrPubkey::from_str("f14d7e54ff58c5d019ce9986be4a0e8b7d643bd08ef2cdf1099e1a457865b547").expect("Fail");
  /// let pubkey = SchnorrPubkey::from_str("b33cc9edc096d0a83416964bd3c6247b8fecd256e4efa7870d2c854bdeb33390").expect("Fail");
  /// let obj = SchnorrUtil::new();
  /// let point = obj.compute_sig_point(&msg, &nonce, &pubkey).expect("Fail");
  /// ```
  pub fn compute_sig_point(
    &self,
    msg: &ByteData,
    nonce: &SchnorrPubkey,
    pubkey: &SchnorrPubkey,
  ) -> Result<Pubkey, CfdError> {
    let msg_hex = alloc_c_string(&msg.to_hex())?;
    let nonce_hex = alloc_c_string(&nonce.to_hex())?;
    let pubkey_hex = alloc_c_string(&pubkey.to_hex())?;
    let mut handle = ErrorHandle::new()?;
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
  /// use cfd_rust::{SchnorrUtil, SchnorrSignature, ByteData, SchnorrPubkey};
  /// use std::str::FromStr;
  /// let sig = SchnorrSignature::from_str("6470fd1303dda4fda717b9837153c24a6eab377183fc438f939e0ed2b620e9ee5077c4a8b8dca28963d772a94f5f0ddf598e1c47c137f91933274c7c3edadce8").expect("Fail");
  /// let msg = ByteData::from_str("e48441762fb75010b2aa31a512b62b4148aa3fb08eb0765d76b252559064a614").expect("Fail");
  /// let pubkey = SchnorrPubkey::from_str("b33cc9edc096d0a83416964bd3c6247b8fecd256e4efa7870d2c854bdeb33390").expect("Fail");
  /// let obj = SchnorrUtil::new();
  /// let is_verify = obj.verify(&sig, &msg, &pubkey).expect("Fail");
  /// ```
  pub fn verify(
    &self,
    signature: &SchnorrSignature,
    msg: &ByteData,
    pubkey: &SchnorrPubkey,
  ) -> Result<bool, CfdError> {
    let sig_hex = alloc_c_string(&signature.to_hex())?;
    let msg_hex = alloc_c_string(&msg.to_hex())?;
    let pubkey_hex = alloc_c_string(&pubkey.to_hex())?;
    let mut handle = ErrorHandle::new()?;
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
