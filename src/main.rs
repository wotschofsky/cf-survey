use actix_web::{get, App, HttpRequest, HttpResponse, HttpServer, Responder};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::Utc;
use clickhouse::{Client, Row};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::env;

#[derive(Row, Serialize)]
struct RequestEntry {
    ip_hash: String,
    ray: String,
    country: String,
    isp: String,
    timestamp: u32,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Get ClickHouse URL from environment variable, exit if not defined
    let clickhouse_url = env::var("CLICKHOUSE_URL").unwrap_or_else(|_| {
        eprintln!("Environment variable CLICKHOUSE_URL is not set.");
        std::process::exit(1);
    });
    println!("Successfully connected to ClickHouse at {}", clickhouse_url);

    // Start HTTP server
    println!("Starting HTTP server on 0.0.0.0:8080");
    HttpServer::new(move || {
        App::new()
            .app_data(actix_web::web::Data::new(clickhouse_url.clone()))
            .service(index)
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}

#[get("/")]
async fn index(req: HttpRequest, clickhouse_url: actix_web::web::Data<String>) -> impl Responder {
    // Extract and process headers
    let (ip_hash, ray, ip_str) = extract_headers(&req);

    // Get timestamp
    let timestamp = Utc::now().timestamp() as u32;

    // Get ISP and country from IP API
    let (country, isp) = get_ip_info(&ip_str).await;

    // Create request entry
    let request_entry = RequestEntry {
        ip_hash,
        ray,
        country,
        isp,
        timestamp,
    };

    // Store request data to ClickHouse
    if let Err(e) = store_request_to_clickhouse(&request_entry, clickhouse_url.get_ref()).await {
        eprintln!("Error inserting into ClickHouse: {:?}", e);
    }

    // Generate response
    generate_response(&req)
}

// Function to extract headers and compute hashed IP
fn extract_headers(req: &HttpRequest) -> (String, String, String) {
    let headers = req.headers();

    // Get the IP address from headers
    let ip_str = headers
        .get("CF-Connecting-IP")
        .and_then(|hv| hv.to_str().ok())
        .or_else(|| headers.get("X-Forwarded-For").and_then(|hv| hv.to_str().ok()))
        .unwrap_or("0.0.0.0")
        .to_string();

    // Hash the IP address
    let mut hasher = Sha256::new();
    hasher.update(&ip_str);
    let ip_hash = format!("{:x}", hasher.finalize());

    // Get CF-Ray
    let ray = headers
        .get("CF-RAY")
        .and_then(|hv| hv.to_str().ok())
        .unwrap_or("unknown-unknown")
        .to_string();

    (ip_hash, ray, ip_str)
}

// Function to get ISP and country from IP API
async fn get_ip_info(ip: &str) -> (String, String) {
    let api_url = format!("http://ip-api.com/json/{}?fields=status,message,country,isp", ip);

    // Make HTTP request to ip-api.com
    let client = reqwest::Client::new();
    let mut country = "unknown".to_string();
    let mut isp = "unknown".to_string();

    match client.get(&api_url).send().await {
        Ok(response) => {
            match response.json::<Value>().await {
                Ok(json) => {
                    if json["status"] == "success" {
                        if let Some(c) = json["country"].as_str() {
                            country = c.to_string();
                        }
                        if let Some(i) = json["isp"].as_str() {
                            isp = i.to_string();
                        }
                    } else {
                        eprintln!("API error for IP {}: {}", ip, json["message"].as_str().unwrap_or("unknown message"));
                    }
                }
                Err(_) => eprintln!("Failed to parse API response"),
            }
        }
        Err(_) => eprintln!("Failed to reach ip-api.com"),
    }

    (country, isp)
}

// Function to store request data to ClickHouse
async fn store_request_to_clickhouse(
    request_entry: &RequestEntry,
    clickhouse_url: &str,
) -> Result<(), clickhouse::error::Error> {
    let ch_client = Client::default()
        .with_url(clickhouse_url)
        .with_database("default");

    let mut insert = ch_client.insert("requests")?;
    insert.write(request_entry).await?;
    insert.end().await?;
    Ok(())
}

// Function to generate appropriate response
fn generate_response(req: &HttpRequest) -> HttpResponse {
    let headers = req.headers();
    // Check Accept header
    let accept = headers
        .get("Accept")
        .and_then(|hv| hv.to_str().ok())
        .unwrap_or("");

    if accept.contains("image") {
        // Return a 1x1 transparent PNG image
        let img_data = STANDARD.decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQV\
                 R42mP8/5+hHgAHggJ/PTrZ3AAAAABJRU5ErkJggg=="
        ).unwrap();
        HttpResponse::Ok()
            .content_type("image/png")
            .body(img_data)
    } else {
        // Return static HTML file
        HttpResponse::Ok()
            .content_type("text/html")
            .body(include_str!("../static/index.html"))
    }
}
