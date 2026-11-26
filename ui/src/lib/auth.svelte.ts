import { loadConfig, getOidcConfig } from './config.svelte';

interface Session {
	/** The ID token, sent to the registry as a bearer. */
	token: string;
	/** The token's `exp`, in milliseconds. */
	expiresAt: number;
	/** What the top bar shows for the signed-in user. */
	subject: string;
}

interface Pending {
	verifier: string;
	state: string;
	nonce: string;
	/** Where the user was when they signed in, returned to afterwards. */
	origin: string;
}

const SESSION_KEY = 'angos-oidc-session';
const PENDING_KEY = 'angos-oidc-pending';
/** Set by Sign out, so no tab signs straight back in through the provider's
 * own session; cleared by the next sign-in the user starts. */
const SIGNED_OUT_KEY = 'angos-oidc-signed-out';

/** Whether this load is the provider redirecting back with a sign-in's answer. */
const returning =
	typeof location !== 'undefined' &&
	['code', 'error'].some((name) => new URLSearchParams(location.search).has(name));

/** One automatic sign-in per page load, so a token the registry keeps
 * refusing cannot bounce the browser between here and the provider. A load
 * returning from the provider is that sign-in's own, and a failure has to
 * stay on screen. */
let attempted = returning;

/** The browser is being handed to the provider. The page's requests until it
 * leaves go out anonymous and are refused, so their errors are not shown. */
let underway = $state(false);

/** What went wrong with the sign-in this load returned from. */
let failure: string | null = $state(null);

export function signingIn(): boolean {
	return underway;
}

export function signInFailure(): string | null {
	return failure;
}

function base64url(bytes: Uint8Array): string {
	return btoa(String.fromCharCode(...bytes))
		.replace(/\+/g, '-')
		.replace(/\//g, '_')
		.replace(/=+$/, '');
}

function randomString(): string {
	return base64url(crypto.getRandomValues(new Uint8Array(32)));
}

async function codeChallenge(verifier: string): Promise<string> {
	const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
	return base64url(new Uint8Array(digest));
}

/** A JWT's payload, unverified: the registry is what validates the token. */
function decodeClaims(token: string): Record<string, unknown> {
	try {
		const payload = token.split('.')[1] ?? '';
		const base64 = payload
			.replace(/-/g, '+')
			.replace(/_/g, '/')
			.padEnd(Math.ceil(payload.length / 4) * 4, '=');
		const bytes = Uint8Array.from(atob(base64), (character) => character.charCodeAt(0));
		return JSON.parse(new TextDecoder().decode(bytes));
	} catch {
		return {};
	}
}

function claimString(claims: Record<string, unknown>, name: string): string | null {
	const value = claims[name];
	return typeof value === 'string' ? value : null;
}

function sessionFromToken(token: string): Session | null {
	const claims = decodeClaims(token);
	if (typeof claims.exp !== 'number') return null;
	return {
		token,
		expiresAt: claims.exp * 1000,
		subject:
			claimString(claims, 'preferred_username') ??
			claimString(claims, 'email') ??
			claimString(claims, 'name') ??
			claimString(claims, 'sub') ??
			'signed in'
	};
}

function parseSession(stored: string | null): Session | null {
	if (!stored) return null;
	try {
		return JSON.parse(stored);
	} catch {
		return null;
	}
}

/** Kept in local storage, so every tab and window of the registry shares one
 * sign-in until the token expires, rather than each repeating the redirects.
 * Storage the browser blocks only costs that sharing. */
function loadSession(): Session | null {
	if (typeof window === 'undefined') return null;
	try {
		return parseSession(localStorage.getItem(SESSION_KEY));
	} catch {
		return null;
	}
}

let session: Session | null = $state(loadSession());

if (typeof window !== 'undefined') {
	// Another tab signing in or out signs this one in or out too.
	window.addEventListener('storage', (event) => {
		if (event.key === SESSION_KEY) session = parseSession(event.newValue);
	});
}

function setSignedOut(signedOut: boolean) {
	try {
		if (signedOut) {
			localStorage.setItem(SIGNED_OUT_KEY, '1');
		} else {
			localStorage.removeItem(SIGNED_OUT_KEY);
		}
	} catch {
		// Blocked storage: nothing outlives this page anyway.
	}
}

function signedOut(): boolean {
	try {
		return localStorage.getItem(SIGNED_OUT_KEY) !== null;
	} catch {
		return false;
	}
}

function storeSession(next: Session | null) {
	session = next;
	try {
		if (next) {
			localStorage.setItem(SESSION_KEY, JSON.stringify(next));
		} else {
			localStorage.removeItem(SESSION_KEY);
		}
	} catch {
		// Blocked storage: the session lives in this page only.
	}
}

/** The session while it is still valid. There is no refresh token, so an
 * expired one is simply not sent and means signing in again. */
function currentSession(): Session | null {
	return session && session.expiresAt > Date.now() ? session : null;
}

export function authHeaders(): Record<string, string> {
	const active = currentSession();
	return active ? { Authorization: `Bearer ${active.token}` } : {};
}

export function signedInAs(): string | null {
	return currentSession()?.subject ?? null;
}

/** Whether sign-in is offered at all, which takes a configured `[ui.oidc]`. */
export function signInAvailable(): boolean {
	return getOidcConfig() !== null;
}

/**
 * The browser's own credentials to send with a registry request. With sign-in
 * offered the bearer is the only credential the UI uses, so the browser's are
 * left out: a refusal's Basic challenge then cannot raise its password dialog.
 * Without it they go along, for a Basic login or an authenticating proxy.
 */
export async function fetchCredentials(): Promise<RequestCredentials> {
	await loadConfig();
	return signInAvailable() ? 'omit' : 'same-origin';
}

export function signOut() {
	storeSession(null);
	setSignedOut(true);
	// Reloaded for the same reason signing in is: the views hold what the
	// session could see, and nothing refetches them where they are.
	location.reload();
}

/** The one URI the provider has to allow, the same for every page the user
 * signs in from: where they were is restored from storage afterwards. */
function redirectUri(): string {
	return `${location.origin}/`;
}

/**
 * Sends the browser to the provider by way of the registry, which discovers
 * the authorization endpoint itself: the provider is never called from the
 * page, so it needs to serve no CORS headers.
 */
export async function signIn(): Promise<void> {
	await loadConfig();
	if (!signInAvailable()) return;
	setSignedOut(false);
	underway = true;

	const pending: Pending = {
		verifier: randomString(),
		state: randomString(),
		nonce: randomString(),
		origin: location.href
	};
	sessionStorage.setItem(PENDING_KEY, JSON.stringify(pending));

	const params = new URLSearchParams({
		redirect_uri: redirectUri(),
		state: pending.state,
		nonce: pending.nonce,
		code_challenge: await codeChallenge(pending.verifier)
	});
	location.assign(`/v2/_angos/ui/oidc/authorize?${params}`);
}

/** Starts sign-in on the first request the registry refuses, so a private
 * registry needs no click while a public one is still browsed anonymously.
 * Not after Sign out, which would otherwise sign straight back in through the
 * provider's own session. A bearer the registry refused is dropped, so
 * signing in again replaces it. */
export async function signInOnUnauthorized(): Promise<void> {
	if (attempted || signedOut()) return;
	attempted = true;
	if (session) storeSession(null);
	// The first refusal can arrive before the configuration saying whether
	// sign-in is offered at all.
	await loadConfig();
	if (signInAvailable()) await signIn();
}

/** The registry's reason for a failed exchange, which carries the provider's. */
async function refusal(response: Response): Promise<string> {
	try {
		const message = (await response.json())?.errors?.[0]?.message;
		if (typeof message === 'string') return `Sign-in failed: ${message}`;
	} catch {
		// Not the registry's error body: the status is all there is.
	}
	return `Sign-in failed (HTTP ${response.status})`;
}

/** The registry redeems the code, adding the client secret when it holds
 * one, and answers the ID token alone. */
async function exchangeCode(code: string, pending: Pending): Promise<string> {
	const response = await fetch('/v2/_angos/ui/oidc/token', {
		method: 'POST',
		headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({
			code,
			code_verifier: pending.verifier,
			redirect_uri: redirectUri()
		})
	});
	if (!response.ok) {
		throw new Error(await refusal(response));
	}

	const body = await response.json();
	if (typeof body.id_token !== 'string') {
		throw new Error('The registry returned no ID token');
	}
	return body.id_token;
}

/** Redeems the code the provider returned with, storing the session it
 * yields. Returns what went wrong, or `null` when nothing did. */
async function redeem(params: URLSearchParams, pending: Pending): Promise<string | null> {
	const refused = params.get('error');
	if (refused) return `Sign-in was refused: ${refused}`;
	// An unsolicited or replayed redirect: the code was not requested here.
	if (params.get('state') !== pending.state) {
		return 'Sign-in failed: the provider returned an unexpected state';
	}

	try {
		const token = await exchangeCode(params.get('code') ?? '', pending);
		if (decodeClaims(token).nonce !== pending.nonce) {
			return 'Sign-in failed: the ID token was issued for another request';
		}
		const established = sessionFromToken(token);
		if (!established) return 'Sign-in failed: the ID token carries no expiry';
		storeSession(established);
		return null;
	} catch (e) {
		return e instanceof Error ? e.message : 'Sign-in failed';
	}
}

/**
 * Runs before the app starts. On the load the provider returns to, redeems
 * the code and puts the address back to the page the user left, so the app
 * starts there, signed in, with no further load. On any other load, renews a
 * session that has lapsed before anything renders and is refused.
 */
export async function finishSignIn(): Promise<void> {
	if (!returning) {
		if (session && !currentSession()) {
			attempted = true;
			storeSession(null);
			await signIn();
		}
		return;
	}

	const stored = sessionStorage.getItem(PENDING_KEY);
	sessionStorage.removeItem(PENDING_KEY);
	if (!stored) return;
	const pending: Pending = JSON.parse(stored);

	failure = await redeem(new URLSearchParams(location.search), pending);
	history.replaceState(history.state, '', pending.origin);
}
