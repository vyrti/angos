import type { ClientInit } from '@sveltejs/kit/hooks';
import { finishSignIn } from '#lib/auth.svelte.js';

// A sign-in returning from the provider is finished before the first page
// renders, so the browser goes from the provider to that page in one load.
export const init: ClientInit = finishSignIn;
