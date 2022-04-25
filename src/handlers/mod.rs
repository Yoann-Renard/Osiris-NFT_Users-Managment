use actix_web::{web, web::ServiceConfig, HttpResponse};
mod authentication;
mod user;
use crate::errors::AppError;


use user::{create_user, update_profile,test,suppr_account,get_your_name};



type AppResult<T> = Result<T, AppError>;
type AppResponse = AppResult<HttpResponse>;


pub fn app_config(config : &mut ServiceConfig) {

    let signup = web::resource("/signup").route(web::post().to(create_user));

   // let get_users = web::resource("/get_users").route(web::get().to(get_users));

    let test = web::resource("/test").route(web::get().to(test));
    
    let suppr_account = web::resource("/suppr_account").route(web::get().to(suppr_account));

    let get_your_name = web::resource("/get_your_name").route(web::get().to(get_your_name));
    
    let me = web::resource("/me")
       // .route(web::get().to(me))
        .route(web::post().to(update_profile));

    config.service(signup).service(me).service(test).service(suppr_account).service(get_your_name);//.service(get_users)
}