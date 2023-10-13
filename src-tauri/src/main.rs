// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![allow(unused)]

use dotenv::dotenv;
use home::home_dir;
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, revocation::StandardRevocableToken,
    AccessToken, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge,
    RedirectUrl, RevocationUrl, Scope, TokenResponse, TokenUrl,
};
use reqwest;
use serde_json::json;
use std::fs;
use std::fs::read_to_string;
use std::io::{BufRead, BufReader, Write};
use std::time::{Duration, Instant};
use tauri::{EventHandler, Manager, RunEvent, WindowEvent};
use tokio::sync::Mutex;
use tracing::{error, info, warn};

pub const MAIN_DATA_FILENAME: &str = r#".tauri_oauth"#;

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Default)]
/// # User
/// struct for the google user data
pub struct User {
    pub id: String,
    pub email: String,
    pub verified_email: bool,
    pub name: String,
    pub given_name: String,
    pub family_name: String,
    pub picture: String,
    pub locale: String,
}

impl User {
    pub fn new() -> Self {
        User {
            id: "".to_string(),
            email: "".to_string(),
            verified_email: false,
            name: "".to_string(),
            given_name: "".to_string(),
            family_name: "".to_string(),
            picture: "".to_string(),
            locale: "".to_string(),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Default)]
/// # UserData
/// are the central data of the application and are stored in a local file and <br>
/// read with the start of the server or initialized if the file does not yet exist.
/// - user
/// - refresh_token
pub struct UserData {
    pub user: User,
    pub refresh_token: Option<oauth2::RefreshToken>,
}

impl UserData {
    ///constructor from user_data as clone()
    pub fn new(user_data: &User) -> Self {
        info!("UserData new()");

        UserData {
            user: user_data.clone(),
            refresh_token: None,
        }
    }

    ///consturctor from file
    pub fn init_user_data() -> Self {
        info!("UserData init_main_data()");

        let home_dir = home_dir().unwrap_or("".into());

        let file_and_path = format!(
            "{}/{}",
            home_dir.to_str().unwrap_or("").to_string(),
            MAIN_DATA_FILENAME
        );

        let user_data_string = read_to_string(file_and_path).unwrap_or("".to_string());

        let user_data = match serde_json::from_str(&user_data_string) {
            Ok(result) => result,
            Err(err) => {
                warn!(?err, "warn: ");
                UserData {
                    user: User::new(),
                    refresh_token: None,
                }
            }
        };
        info!("user_data: {:#?}", user_data);
        return user_data;
    }

    ///set and save the main_data
    pub fn set(&mut self, email: String, name: String) {
        self.user.email = email;
        self.user.name = name;
        self.save_me();
    }

    pub fn set_token(&mut self, refresh_token: Option<oauth2::RefreshToken>) {
        self.refresh_token = refresh_token.clone();
        self.save_me();
    }

    ///save refresh token from UserData in file
    pub fn save_me(&self) {
        info!("UserData save_me()");

        let home_dir = home_dir().unwrap_or("".into());

        let file_and_path = format!(
            "{}/{}",
            home_dir.to_str().unwrap_or("").to_string(),
            MAIN_DATA_FILENAME
        );

        let main_data_json = json!(self).to_string();

        match fs::write(file_and_path, main_data_json) {
            Ok(_) => {}
            Err(err) => {
                error!(?err, "Error: ");
            }
        };
    }

    /// ## log_in()
    /// call ``get_token()`` OAuth and then get the userdate <br>
    /// ``bool`` Return value returns ``logged_in`` if the OAuth 
    /// was successful and supplied an access token.
    /// In addition, this token is then used to retrieve the 
    /// user data is retrieved.
    /// Only if both actions were successful ``true`` is returned. 
    /// is returned.  
    pub async fn log_in(&mut self, window: &tauri::Window) -> bool {
        let l_do: i32 = 'block: {
            let (l_access_token, l_refresh_token) =
                match get_token(&window, self.user.email.clone(), self.refresh_token.clone()).await
                {
                    Ok(token) => token,
                    Err(e) => {
                        error!("error - Access token could not be retrieved {}", e);

                        self.user.name = "".to_string();
                        self.user.email = "".to_string();
                        self.refresh_token = None;

                        self.save_me();

                        return false;
                    }
                };

            let url = format!(
                "https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token={:?}",
                l_access_token.secret()
            );

            let resp = match reqwest::get(url).await {
                Ok(res) => match res.text().await {
                    Ok(res_text) => res_text,
                    Err(e) => {
                        error!("error - userinfo could not be retrieved {}", e);
                        return false;
                    }
                },
                Err(e) => {
                    error!("error - userinfo could not be retrieved {}", e);
                    return false;
                }
            };
            info!(?resp, "userinfo: ");

            let userinfo: User = match serde_json::from_str(&resp) {
                Ok(result) => result,
                Err(_) => User {
                    id: "".to_string(),
                    email: "".to_string(),
                    verified_email: false,
                    name: "".to_string(),
                    given_name: "".to_string(),
                    family_name: "".to_string(),
                    picture: "".to_string(),
                    locale: "".to_string(),
                },
            };

            self.user = userinfo;

            if self.user.email.is_empty() {
                //if invalide email clear token
                self.set_token(None);
                self.save_me();
                return false;
            }

            self.save_me();

            if l_refresh_token.is_some() {
                info!("refresh_token found");

                self.set_token(l_refresh_token);

                return true;
            }
            if !l_access_token.secret().is_empty() {
                self.save_me();

                return true;
            }
            99
        };

        false
    }
}

/// # AppData
/// is managed via the tauri app
pub struct AppData {
    pub user_data: Mutex<UserData>,
    pub logged_in: Mutex<bool>,
    //pub db: Mutex<SqliteConnection>,
}

/// # get_token
/// Function to determine the access token for access to gmail
///
/// https://developers.google.com/identity/protocols/
async fn get_token(
    window: &tauri::Window,
    email: String,
    refresh_token: Option<oauth2::RefreshToken>,
) -> Result<(AccessToken, Option<oauth2::RefreshToken>), Box<dyn std::error::Error>> {
    //get the google client ID and the client secret from .env file
    dotenv().ok();

    let google_client_id = ClientId::new(std::env::var("GOOGLE_CLIENT_ID")?);
    let google_client_secret = ClientSecret::new(std::env::var("GOOGLE_CLIENT_SECRET")?);
    let auth_url = AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())?; //.expect("Invalid authorization endpoint URL");
    let token_url = TokenUrl::new("https://www.googleapis.com/oauth2/v3/token".to_string())?; //.expect("Invalid token endpoint URL");

    // Set up the config for the Google OAuth2 process.
    let client = BasicClient::new(
        google_client_id,
        Some(google_client_secret),
        auth_url,
        Some(token_url),
    )
    // This example will be running its own server at http://127.0.0.1:1421
    // See below for the server implementation.
    .set_redirect_uri(
        RedirectUrl::new("http://127.0.0.1:1421".to_string())?, //.expect("Invalid redirect URL"),
    )
    // Google supports OAuth 2.0 Token Revocation (RFC-7009)
    .set_revocation_uri(
        RevocationUrl::new("https://oauth2.googleapis.com/revoke".to_string())?, //.expect("Invalid revocation endpoint URL"),
    ); //.set_introspection_uri(introspection_url);

    if refresh_token.is_some() {
        println!("get_token() refresh_token found");

        match client
        .exchange_refresh_token(&refresh_token.unwrap().clone())
        .request_async(async_http_client)
        .await {
            Ok(token_response) => {
                let access_token = token_response.access_token().clone();
                let refresh_token = token_response.refresh_token().cloned();
                return Ok((access_token, refresh_token));
            },
            Err(_) => {},
        };
        println!("get_token() refresh_token not valid, login required");
    }

    // Google supports Proof Key for Code Exchange (PKCE - https://oauth.net/2/pkce/).
    // Create a PKCE code verifier and SHA-256 encode it as a code challenge.
    let (pkce_code_challenge, pkce_code_verifier) = PkceCodeChallenge::new_random_sha256();

    // Generate the authorization URL to which we'll redirect the user.
    let (authorize_url, csrf_state) = client
        .authorize_url(CsrfToken::new_random)
        // This example is requesting access to the "gmail" features and the user's profile.
        //.add_scope(Scope::new("https://mail.google.com".into()))
        .add_scope(Scope::new("profile email".into()))
        .add_extra_param("access_type", "offline")
        .add_extra_param("login_hint", email)
        //.add_extra_param("prompt", "none")
        .set_pkce_challenge(pkce_code_challenge)
        .url();

    println!("The authorization URL is:\n{}\n", authorize_url.to_string());

    let handle = window.app_handle();

    let login_window = tauri::WindowBuilder::new(
        &handle,
        "Google_Login", /* the unique window label */
        tauri::WindowUrl::External(
            authorize_url.to_string().parse()?, //.expect("error WindowBuilder WindowUrl parse"),
        ),
    )
    .build()?; //.expect("error WindowBuilder build");
    login_window.set_title("Google Login");
    login_window.set_always_on_top(true);

    // A very naive implementation of the redirect server.
    let listener = std::net::TcpListener::bind("127.0.0.1:1421")?; //.expect("error TcpListener bind");
    let local_addr = listener.local_addr()?;

    let timer = timer::Timer::new();

    let _guard = timer.schedule_with_delay(chrono::Duration::seconds(25), move || {
        //the time out as connect to close server
        let _ = std::net::TcpStream::connect(local_addr); 
    });

    login_window.on_window_event(move |event| {
        if let WindowEvent::CloseRequested { api, .. } = &event {
        info!("event close-requested");
        let _ = std::net::TcpStream::connect(local_addr); //connect to server to close it
        };
    });

    //this is blocking listener! we use guard schedule for time out
    for stream in listener.incoming() {
        let _ = login_window.is_visible()?; //check if login_window is visible

        if let Ok(mut stream) = stream {
            info!("listener stream");

            let code;
            let state;
            let errorinfo;
            {
                let mut reader = BufReader::new(&stream);

                let mut request_line = String::new();
                reader.read_line(&mut request_line)?;

                let redirect_url = match request_line.split_whitespace().nth(1) {
                    Some(url_data) => url_data,
                    _ => {
                        login_window.close()?;
                        break;
                    }
                };
                println!("redirect_url: \n{}", redirect_url.clone());
                let url = url::Url::parse(&("http://localhost".to_string() + redirect_url))?;

                use std::borrow::Cow;
                //extract code from url
                let code_pair = url
                    .query_pairs()
                    .find(|pair| {
                        let &(ref key, _) = pair;
                        key == "code"
                    })
                    .unwrap_or((Cow::from(""), Cow::from("")));

                let (_, value) = code_pair;
                code = AuthorizationCode::new(value.into_owned());

                //extract state from url
                let state_pair = url
                    .query_pairs()
                    .find(|pair| {
                        let &(ref key, _) = pair;
                        key == "state"
                    })
                    .unwrap_or((Cow::from(""), Cow::from("")));

                let (_, value) = state_pair;
                state = CsrfToken::new(value.into_owned());

                //extract error from url
                let errorinfo_pair = url
                    .query_pairs()
                    .find(|pair| {
                        let &(ref key, _) = pair;
                        key == "error"
                    })
                    .unwrap_or((Cow::from(""), Cow::from("")));

                let (_, value) = errorinfo_pair;
                errorinfo = String::from(value.into_owned());
            }

            //if error found
            if !errorinfo.is_empty() {
                login_window.close()?;
                Err(errorinfo)?
            }

            let message = "Verification completed, please close window.";
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{}",
                message.len(),
                message
            );
            stream.write_all(response.as_bytes())?;

            println!("Google returned the following code:\n{}\n", code.secret());
            println!(
                "Google returned the following state:\n{} (expected `{}`)\n",
                state.secret(),
                csrf_state.secret()
            );

            // Exchange the code with a token.
            let token_response = match client
                .exchange_code(code)
                .set_pkce_verifier(pkce_code_verifier)
                .request_async(async_http_client)
                .await
            {
                Ok(res) => res,
                Err(err) => {
                    login_window.close()?;
                    Err("--  no permission --")?
                }
            };

            println!("\n{:#?}", token_response);

            // println!(
            //     "\naccess-token:\n{:#?}\ntoken_type:\n{:#?}\
            //     \nexpires_in\n{:#?}\nrefresh_token\n{:#?}\
            //     \nscopes\n{:#?}\nextra_fields\n{:#?}",
            //     token_response.access_token().clone(),
            //     token_response.token_type().clone(),
            //     token_response.expires_in().clone(),
            //     token_response.refresh_token().clone(),
            //     token_response.scopes().clone(),
            //     token_response.extra_fields().clone()
            // );

            let access_token = token_response.access_token().clone();
            let refresh_token = token_response.refresh_token().cloned();

            println!("Google returned the following token:\n{:?}\n", access_token);

            // // Revoke the obtained token
            // let token_response = token_response.unwrap();
            // let token_to_revoke: StandardRevocableToken = match token_response.refresh_token() {
            //     Some(token) => token.into(),
            //     None => token_response.access_token().into(),
            // };

            // client
            //     .revoke_token(token_to_revoke)
            //     .unwrap()
            //     .request_async(async_http_client).await
            //     //.request(http_client)
            //     .expect("Failed to revoke token");

            login_window.close()?; //.expect("error closw login window");

            return Ok((access_token, refresh_token));
            // The server will terminate itself after revoking the token.
            break;
        } else {
            println!("error on stream");
            break;
        }
    } //listener.incoming() loop

    Err("-- login window time out --")?

    //return "".to_string(); //token_result.access_token().clone();
}

// A function that sends a message from Rust to JavaScript via a Tauri Event
pub fn rs2js<R: tauri::Runtime>(message: String, manager: &impl tauri::Manager<R>) {
    let mut sub_message = message.clone();
    sub_message.truncate(50);
    info!(?sub_message, "rs2js");
    match manager.emit_all("rs2js", message) {
        Ok(_) => {}
        Err(err) => {
            error!(?err);
        }
    };
}

/// The Tauri command that gets called when Tauri `invoke` JavaScript API is called
#[tauri::command(async)]
async fn js2rs(
    window: tauri::Window,
    message: String,
    app_data: tauri::State<'_, AppData>,
) -> Result<String, String> {
    info!(message, "message_handler: ");

    if message == "get_user" {
        //get the data from the mutex
        let mut user_data = app_data.user_data.lock().await;
        let mut logged_in = app_data.logged_in.lock().await;

        if logged_in.clone() != true {
            match window.get_window("main") {
                Some(main_window) => {
                    main_window.hide();

                    *logged_in = user_data.log_in(&window).await;

                    main_window.show();
                }
                _ => {}
            };
        }

        return Ok(json!(user_data.user).to_string());
    }

    if message == "logout" {
        //get the data from the mutex
        let mut user_data = app_data.user_data.lock().await;
        let mut logged_in = app_data.logged_in.lock().await;

        //clear all user data
        user_data.user = User::new();
        user_data.refresh_token = None;
        user_data.save_me();
        *logged_in = false;

        *logged_in = user_data.log_in(&window).await;

        return Ok(json!(user_data.user).to_string());
    }

    //return else
    Ok("".to_string())
}

fn main() {
    tracing_subscriber::fmt::init();

    let app = tauri::Builder::default()
        .manage(AppData {
            user_data: UserData::init_user_data().into(), //the user data
            logged_in: false.into(),                      //log in state
                                                          //db: establish_connection(&database_name).into(),
        }) // AppData to manage
        .invoke_handler(tauri::generate_handler![js2rs])
        .build(tauri::generate_context!())   
        .unwrap()
        .run(move |_app_handler, _event| {
            if let RunEvent::ExitRequested { api, .. } = &_event {
                println!("Exit requested: {:?}", _event);
                // Keep the event loop running even if all windows are closed
                // This allow us to catch tray icon events when there is no window
                //api.prevent_exit();
              }            
        });

        //.expect("error while running tauri application");
}
