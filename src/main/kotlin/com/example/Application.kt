package com.example

import com.typesafe.config.ConfigFactory
import io.ktor.client.*
import io.ktor.client.engine.cio.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.config.*
import io.ktor.server.engine.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.sessions.*
import java.security.SecureRandom

val applicationHttpClient = HttpClient(CIO) {
    install(ContentNegotiation) {
        json()
    }
}

fun Application.module(httpClient: HttpClient = applicationHttpClient) {
    val redirectHost = environment.config.tryGetString("ktor.deployment.redirectHost")
    val port = (environment as ApplicationEngineEnvironment).connectors.first().port
    install(Authentication) {
        oauth("auth-oauth-mal") {
            val secureRandom = SecureRandom()
            val bytes = ByteArray(64)
            secureRandom.nextBytes(bytes)
            val codeVerifier = bytes.toHexString()
            val clientId = System.getenv("MAL_CLIENT_ID")
            val clientSecret = System.getenv("MAL_CLIENT_SECRET")
            urlProvider = { "http://$redirectHost:$port/callback" }
            providerLookup = {
                OAuthServerSettings.OAuth2ServerSettings(
                    name = "mal",
                    authorizeUrl = "https://myanimelist.net/v1/oauth2/authorize",
                    accessTokenUrl = "https://myanimelist.net/v1/oauth2/token",
                    requestMethod = HttpMethod.Post,
                    clientId,
                    clientSecret,
                    extraAuthParameters = listOf(
                        "code_challenge_method" to "plain", "code_challenge" to codeVerifier
                    ),
                    extraTokenParameters = listOf(
                        "client_id" to clientId,
                        "client_secret" to clientSecret,
                        "grant_type" to "authorization_code",
                        "code_verifier" to codeVerifier
                    )
                )
            }
            client = httpClient
        }
    }
    routing {
        authenticate("auth-oauth-mal") {
            get("/login") {}
            get("/callback") {
                val principal: OAuthAccessTokenResponse.OAuth2? = call.principal()
                call.response.cookies.append(
                    name = "access_token",
                    value = principal?.accessToken.toString(),
                    // want to use short-lived cookie bc can't access response headers from web view apparently
                    maxAge = 0L
                )
                call.respondRedirect("/")
            }
        }
        get("/logout") {
            call.respond(HttpStatusCode.OK)
        }
    }
}

fun ByteArray.toHexString() = joinToString("") { "%02x".format(it) }

fun main(args: Array<String>): Unit = io.ktor.server.netty.EngineMain.main(args)
