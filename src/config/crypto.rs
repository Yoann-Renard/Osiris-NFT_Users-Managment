use color_eyre::Result;
use std::sync::Arc;
use argonautica::{Hasher,Verifier,input::Salt};
use futures::compat::Future01CompatExt;
use eyre::eyre;
use tracing::instrument;
use uuid::Uuid;
use serde::{Serialize,Deserialize};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, TokenData, Validation};
use actix_web::web::block;
use chrono::{Duration, Utc};

#[derive(Debug,Clone)]
pub struct CryptoService{
    pub key : Arc<String>,
    pub jwt_secret : Arc<String> //A thread-safe reference-counting pointer. 'Arc' stands for 'Atomically Reference Counted'.
}

#[derive(Serialize,Deserialize)]
pub struct Permissions{
    pub sub: Uuid,
    pub exp: i64
}

#[derive(Serialize)]
pub struct Auth {
    pub token: String,
}

    
    //_________________________________________________________________________//
    //config par default du hasher 


    // backend: Backend::C
    // cpu_pool: A CpuPool ...
    //     with threads equal to the number of logical cores on your machine
    //     that is lazily created, i.e. created only if / when you call the methods that need it (hash_non_blocking or hash_raw_non_blocking)
    // hash_len: 32 bytes
    // iterations: 192
    // lanes: The number of logical cores on your machine
    // memory_size: 4096 kibibytes
    // opt_out_of_secret_key: false
    // password_clearing: false
    // salt: random Salt of length 32 bytes that renews with every hash
    // secret_key_clearing: false
    // threads: The number of logical cores on your machine
    // variant: Variant::Argon2id
    // version: Version::_0x13


impl CryptoService {
    #[instrument(skip(self,password))]
    pub async fn hash_password(&self, password : String) -> Result<String> {
       
        Hasher::default()
            .with_secret_key(&*self.key)
            .with_password(password)
            .hash_non_blocking()    //return an old version of our futures
            .compat()
            .await
            .map_err(|err| eyre!("hash error : {:?}", err))
    }

    #[instrument(skip(self))]
    pub async fn generate_jwt(&self , user_id:Uuid) -> Result<String>{

        let jwt_key = self.jwt_secret.clone();
        block(move || {
            let headers = Header::default();
            let encodingkey = EncodingKey::from_secret(jwt_key.as_bytes());
            let now = Utc::now() + Duration::days(1); // expires in a day
            let permissions = Permissions {
                sub : user_id,
                exp : now.timestamp(),
            };
            encode(&headers,&permissions,&encodingkey)
        })
        .await
        .map_err(|err| eyre!("Creating jwt token: {}", err))

    }

    #[instrument(skip(self, token))]
    pub async fn verify_jwt(&self, token: String) -> Result<TokenData<Permissions>> {
        let jwt_key = self.jwt_secret.clone();
        block(move || {
            let decoding_key = DecodingKey::from_secret(jwt_key.as_bytes());
            let validation = Validation::default();
            decode::<Permissions>(&token, &decoding_key, &validation)
        })
        .await
        .map_err(|err| eyre!("Verifying jwt token: {}", err))
    }


}