import { goto } from '$app/navigation';
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

/** Whether this load is the provider redirecting back with a sign-in's answer. */
const returning =
	typeof location !== 'undefined' &&
	['code', 'error'].some((name) => new URLSearchParams(location.search).has(name));

/** One automatic sign-in per page load, so a token the registry keeps
 * refusing cannot bounce the browser between here and the provider. A load
 * returning from the provider is that sign-in's own: the page's first requests
 * are refused before the code is redeemed, and a failure has to stay on screen. */
let attempted = returning;

/** A sign-in under way: the browser is being handed to the provider, or this
 * load is its return and the code is not yet redeemed. The page's requests in
 * between go out anonymous and are refused, so their errors are not shown. */
let underway = $state(returning);

export function signingIn(): boolean {
	return underway;
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

function storedSession(): Session | null {
	if (typeof sessionStorage === 'undefined') return null;
	const stored = sessionStorage.getItem(SESSION_KEY);
	if (!stored) return null;
	try {
		return JSON.parse(stored);
	} catch {
		return null;
	}
}

let session: Session | null = $state(storedSession());

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
	session = null;
	sessionStorage.removeItem(SESSION_KEY);
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
 * registry needs no click while a public one is still browsed anonymously. */
export async function signInOnUnauthorized(): Promise<void> {
	if (attempted || currentSession()) return;
	attempted = true;
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

/**
 * Finishes a sign-in the provider redirected back from, then returns the user
 * to the page they left. Does nothing on a page load that is not such a
 * redirect. Returns what went wrong, or `null` when nothing did.
 */
export async function completeSignIn(): Promise<string | null> {
	const params = new URLSearchParams(location.search);
	const code = params.get('code');
	const failure = params.get('error');
	if (!code && !failure) return null;

	const stored = sessionStorage.getItem(PENDING_KEY);
	sessionStorage.removeItem(PENDING_KEY);
	if (!stored) {
		underway = false;
		return null;
	}
	const pending: Pending = JSON.parse(stored);

	// Every failure ends here, and the page it returns to shows what failed.
	const restore = () => {
		underway = false;
		return goto(pending.origin, { replace: true });
	};

	if (failure) {
		await restore();
		return `Sign-in was refused: ${failure}`;
	}
	// An unsolicited or replayed redirect: the code was not requested here.
	if (params.get('state') !== pending.state) {
		await restore();
		return 'Sign-in failed: the provider returned an unexpected state';
	}

	try {
		const token = await exchangeCode(code ?? '', pending);
		if (decodeClaims(token).nonce !== pending.nonce) {
			await restore();
			return 'Sign-in failed: the ID token was issued for another request';
		}
		const established = sessionFromToken(token);
		if (!established) {
			await restore();
			return 'Sign-in failed: the ID token carries no expiry';
		}
		session = established;
		sessionStorage.setItem(SESSION_KEY, JSON.stringify(established));
		// A document load, not a client-side one: the views fetch as they mount,
		// which here already happened without the session, and returning to the
		// route they are on would not mount them again.
		location.replace(pending.origin);
		return null;
	} catch (e) {
		await restore();
		return e instanceof Error ? e.message : 'Sign-in failed';
	}
}
