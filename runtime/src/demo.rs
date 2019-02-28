use rstd::prelude::*;
use runtime_io::{keccak_256, secp256k1_ecdsa_recover};
use support::{decl_module, decl_storage, StorageValue, dispatch::Result}; //decl_event, 
use system::ensure_signed;
use parity_codec_derive::{Encode, Decode};
use parity_codec::Encode;
#[cfg(feature = "std")]
// use runtime_primitives::traits::{Zero};
use balances;

pub trait Trait: balances::Trait {}

type EthereumAddress = [u8; 20];

// This is a bit of a workaround until codec supports [u8; 65] directly.
#[derive(Encode, Decode, Clone, PartialEq)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct EcdsaSignature([u8; 32], [u8; 32], i8);

impl EcdsaSignature {
	pub fn to_blob(&self) -> [u8; 65] {
		let mut r = [0u8; 65];
		r[0..32].copy_from_slice(&self.0[..]);
		r[32..64].copy_from_slice(&self.1[..]);
		r[64] = self.2 as u8;
		r
	}
	pub fn from_blob(blob: &[u8; 65]) -> Self {
		let mut r = Self([0u8; 32], [0u8; 32], 0);
		r.0[..].copy_from_slice(&blob[0..32]);
		r.1[..].copy_from_slice(&blob[32..64]);
		r.2 = blob[64] as i8;
		r
	}
}

// Constructs the message that Ethereum RPC's `personal_sign` and `eth_sign` would sign.
fn ethereum_signable_message(what: &[u8]) -> Vec<u8> {
	let prefix = b"Pay DOTs to the Polkadot account:";
	let mut l = prefix.len() + what.len();
	let mut rev = Vec::new();
	while l > 0 {
		rev.push(b'0' + (l % 10) as u8);
		l /= 10;
	}
	let mut v = b"\x19Ethereum Signed Message:\n".to_vec();
	v.extend(rev.into_iter().rev());
	v.extend_from_slice(&prefix[..]);
	v.extend_from_slice(what);
	v
}

// Attempts to recover the Ethereum address from a message signature signed by using
// the Ethereum RPC's `personal_sign` and `eth_sign`.
fn eth_recover(s: &EcdsaSignature, what: &[u8]) -> Option<EthereumAddress> {
	let msg = keccak_256(&ethereum_signable_message(what));
	let mut res = EthereumAddress::default();
	res.copy_from_slice(&keccak_256(&secp256k1_ecdsa_recover(&s.to_blob(), &msg).ok()?[..])[12..]);
	Some(res)
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        // recover_event

        /// Make a claim.
		fn claim(origin, ethereum_signature: EcdsaSignature) -> Result {
			// This is a public call, so we ensure that the origin is some signed account.
			let sender = ensure_signed(origin)?;
			
			let signer = sender.using_encoded(|data|
					eth_recover(&ethereum_signature, data)
				).ok_or("Invalid Ethereum signature")?;
			
            <Signer<T>>::put(signer);
            // Self::recover_event(RawEvent::Recovered(signer));

            Ok(())
		}
    }
}

decl_storage! {
  trait Store for Module<T: Trait> as Demo {
      Signer get(signer): Option<EthereumAddress>;
  }
}



#[cfg(test)]
mod tests {
	use secp256k1;
	use tiny_keccak::keccak256;
	use super::*;

	use sr_io::{self as runtime_io, with_externalities};
	use substrate_primitives::{H256, Blake2Hasher};
	use codec::{Decode, Encode};
	// The testing primitives are very useful for avoiding having to work with signatures
	// or public keys. `u64` is used as the `AccountId` and no `Signature`s are requried.
	use sr_primitives::{
		BuildStorage, traits::{BlakeTwo256, IdentityLookup}, testing::{Digest, DigestItem, Header}
	};
	use balances;

	impl_outer_origin! {
		pub enum Origin for Test {}
	}

	// For testing the module, we construct most of a mock runtime. This means
	// first constructing a configuration type (`Test`) which `impl`s each of the
	// configuration traits of modules we want to use.
	#[derive(Clone, Eq, PartialEq)]
	pub struct Test;
	impl system::Trait for Test {
		type Origin = Origin;
		type Index = u64;
		type BlockNumber = u64;
		type Hash = H256;
		type Hashing = BlakeTwo256;
		type Digest = Digest;
		type AccountId = u64;
		type Lookup = IdentityLookup<u64>;
		type Header = Header;
		type Event = ();
		type Log = DigestItem;
	}
	impl balances::Trait for Test {
		type Balance = u64;
		type OnFreeBalanceZero = ();
		type OnNewAccount = ();
		type EnsureAccountLiquid = ();
		type Event = ();
	}
	impl Trait for Test {
		type Event = ();
	}
	type Balances = balances::Module<Test>;
	type Claims = Module<Test>;

	fn alice_secret() -> secp256k1::SecretKey {
		secp256k1::SecretKey::parse(&keccak256(b"Alice")).unwrap()
	}
	fn alice_public() -> secp256k1::PublicKey {
		secp256k1::PublicKey::from_secret_key(&alice_secret())
	}
	fn alice_eth() -> EthereumAddress {
		let mut res = EthereumAddress::default();
		res.copy_from_slice(&keccak256(&alice_public().serialize()[1..65])[12..]);
		res
	}
	fn alice_sig(what: &[u8]) -> EcdsaSignature {
		let msg = keccak256(&ethereum_signable_message(what));
		let (sig, recovery_id) = secp256k1::sign(&secp256k1::Message::parse(&msg), &alice_secret()).unwrap();
		let sig: ([u8; 32], [u8; 32]) = Decode::decode(&mut &sig.serialize()[..]).unwrap();
		EcdsaSignature(sig.0, sig.1, recovery_id.serialize() as i8)
	}
	fn bob_secret() -> secp256k1::SecretKey {
		secp256k1::SecretKey::parse(&keccak256(b"Bob")).unwrap()
	}
	fn bob_sig(what: &[u8]) -> EcdsaSignature {
		let msg = keccak256(&ethereum_signable_message(what));
		let (sig, recovery_id) = secp256k1::sign(&secp256k1::Message::parse(&msg), &bob_secret()).unwrap();
		let sig: ([u8; 32], [u8; 32]) = Decode::decode(&mut &sig.serialize()[..]).unwrap();
		EcdsaSignature(sig.0, sig.1, recovery_id.serialize() as i8)
	}

	// This function basically just builds a genesis storage key/value store according to
	// our desired mockup.
	fn new_test_ext() -> sr_io::TestExternalities<Blake2Hasher> {
		let mut t = system::GenesisConfig::<Test>::default().build_storage().unwrap().0;
		// We use default for brevity, but you can configure as desired if needed.
		t.extend(balances::GenesisConfig::<Test>::default().build_storage().unwrap().0);
		t.extend(GenesisConfig::<Test>{
			claims: vec![(alice_eth(), 100)],
		}.build_storage().unwrap().0);
		t.into()
	}

	#[test]
	fn basic_setup_works() {
		with_externalities(&mut new_test_ext(), || {
			assert_eq!(Claims::total(), 100);
			assert_eq!(Claims::claims(&alice_eth()), Some(100));
			assert_eq!(Claims::claims(&[0; 20]), None);
		});
	}

	#[test]
	fn claiming_works() {
		with_externalities(&mut new_test_ext(), || {
			assert_eq!(Balances::free_balance(&42), 0);
			assert_ok!(Claims::claim(Origin::signed(42), alice_sig(&42u64.encode())));
			assert_eq!(Balances::free_balance(&42), 100);
		});
	}

	#[test]
	fn double_claiming_doesnt_work() {
		with_externalities(&mut new_test_ext(), || {
			assert_eq!(Balances::free_balance(&42), 0);
			assert_ok!(Claims::claim(Origin::signed(42), alice_sig(&42u64.encode())));
			assert_noop!(Claims::claim(Origin::signed(42), alice_sig(&42u64.encode())), "Ethereum address has no claim");
		});
	}

	#[test]
	fn non_sender_sig_doesnt_work() {
		with_externalities(&mut new_test_ext(), || {
			assert_eq!(Balances::free_balance(&42), 0);
			assert_noop!(Claims::claim(Origin::signed(42), alice_sig(&69u64.encode())), "Ethereum address has no claim");
		});
	}

	#[test]
	fn non_claimant_doesnt_work() {
		with_externalities(&mut new_test_ext(), || {
			assert_eq!(Balances::free_balance(&42), 0);
			assert_noop!(Claims::claim(Origin::signed(42), bob_sig(&69u64.encode())), "Ethereum address has no claim");
		});
	}

	#[test]
	fn real_eth_sig_works() {
		let sig = hex!["7505f2880114da51b3f5d535f8687953c0ab9af4ab81e592eaebebf53b728d2b6dfd9b5bcd70fee412b1f31360e7c2774009305cb84fc50c1d0ff8034dfa5fff1c"];
		let sig = EcdsaSignature::from_blob(&sig);
		let who = 42u64.encode();
		let signer = eth_recover(&sig, &who).unwrap();
		assert_eq!(signer, hex!["DF67EC7EAe23D2459694685257b6FC59d1BAA1FE"]);
	}

    #[test]
	fn new_real_eth_sig_works() {
		let sig = hex!["73ac8e2c177bc8669853b60e083c6e2fe58f4b2b2fd313767e5044331a223a7d60f4ea6c535b5381ab688bac673b40d109671e79a65a96e0761169029dbd436e1b"];
		let sig = EcdsaSignature::from_blob(&sig);
		let who = 42u64.encode();
		let signer = eth_recover(&sig, &who).unwrap();
		assert_eq!(signer, hex!["2156b0acbb9ae3cee0451f489cd42477c427072a"]);
	}
}