use crate::{config::crypto::CryptoService,
    models::user::{User,Userpass,NewUser,UpdateProfile,Fullname},
    errors::AppError,
    };


use actix_web::{web::Data, FromRequest ,HttpResponse};
use sqlx::{PgPool, postgres::PgQueryAs};
use std::sync::Arc;
use std::ops::Deref;
use color_eyre::Result;
use uuid::Uuid;
use futures::future::{ready,Ready};
use tracing::instrument;

pub struct UserRepository {
    pool: Arc<PgPool>
}

impl UserRepository {
    pub fn new(pool:Arc<PgPool>) -> Self {
        Self {pool}
    }

    pub async fn create(&self, new_user : NewUser, crypto_service : &CryptoService) -> Result<User>{
        let password_hash = crypto_service.hash_password(new_user.password)
        .await?;

        let uuid = Uuid::new_v4();

        let info_user = sqlx::query_as::<_, User>(
            "insert into users_info (id,full_name) values ($1,$2) returning *;"
            //insert into users_pass (id, username, password_hash) values ($1,$4,$5)
        )
        .bind(uuid)
        //.bind(new_user.username)
        .bind(new_user.full_name)

        // .bind(new_user.username)//other table
        // .bind(password_hash)
        .fetch_one(&*self.pool)
        .await?;

        let info_pass = sqlx::query_as::<_, Userpass>(
            "insert into users_pass (id,username, password_hash) values ($1,$2,$3) returning *;"
            //insert into users_pass (id, username, password_hash) values ($1,$4,$5)
        )
        .bind(uuid)
        .bind(new_user.username)
        .bind(password_hash)
        .fetch_one(&*self.pool)
        .await?;

        Ok(info_user)
    } 

    pub async fn update_profile(&self, user_id: Uuid, profile: UpdateProfile) -> Result<User> {
        let user = sqlx::query_as::<_, User>(
            "update users_info set full_name = $2, bio = $3, image = $4 where id = $1 returning *",
        )
        .bind(user_id)
        .bind(profile.full_name)
        .bind(profile.bio)
        .bind(profile.image)
        .fetch_one(&*self.pool)
        .await?;
        Ok(user)
    }

    // #[instrument(skip(self))]
    // pub async fn find_by_username(&self, username: &str) -> Result<User> {
    //     let maybe_user = sqlx::query_as::<_, User>("select * from users where username = $1")
    //         .bind(username)
    //         .fetch_one(&*self.pool)
    //         .await?;

    //     Ok(maybe_user)
    // }

    // #[instrument(skip(self))]
    // pub async fn find_by_id(&self, id: Uuid) -> Result<Option<User>> {
    //     let maybe_user = sqlx::query_as::<_, User>("select * from users where id = $1")
    //         .bind(id)
    //         .fetch_optional(&*self.pool)
    //         .await?;

    //     Ok(maybe_user)
    // }


    #[instrument(skip(self))]
    pub async fn find_full_name_by_id(&self, id: Uuid) -> Result<Option<Fullname>> {
        let maybe_user = sqlx::query_as::<_, Fullname>("select full_name from users_info where id = $1")
            .bind(id)
            .fetch_optional(&*self.pool)
            .await?;

        Ok(maybe_user)
    }


    // #[instrument(skip(self))]
    // pub async fn get_all_users(&self) {

    //     let all_users = sqlx::query!("select username from users")
    //         .fetch_all(&*self.pool)
    //         .await;
        
    //     println!("{:?}\n",all_users);
    // }

    pub async fn db_suppr_account(&self,id_to_suppr : Uuid){
        println!("dans db suppr account");
         
        
    }
}

impl FromRequest for UserRepository {
    type Error = AppError;
    type Future = Ready<Result<Self, Self::Error>>;
    type Config = ();
    #[instrument(skip(req, payload))]
    fn from_request(    
        req: &actix_web::HttpRequest,
        payload: &mut actix_web::dev::Payload,
    ) -> Self::Future {
        let pool_result = Data::<PgPool>::from_request(req, payload).into_inner();

        match pool_result {
            Ok(pool) => ready(Ok(UserRepository::new(pool.deref().clone()))),
            _ => ready(Err(AppError::NOT_AUTHORIZED.default())),
        }
    }
}