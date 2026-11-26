interface OidcConfig {
	issuer: string;
	client_id: string;
	/** The OAuth `scope` parameter, verbatim. */
	scopes: string;
}

interface UiConfig {
	name: string;
	oidc?: OidcConfig;
}

let config: UiConfig = $state({ name: 'angos' });
/** One read per page load, shared by every caller waiting on it. */
let loading: Promise<void> | null = null;

export function loadConfig(): Promise<void> {
	loading ??= (async () => {
		try {
			const response = await fetch('/v2/_angos/ui/config');
			if (response.ok) {
				config = await response.json();
			}
		} catch {
			// Use defaults on error
		}
	})();
	return loading;
}

export function getRegistryName(): string {
	return config.name;
}

export function getOidcConfig(): OidcConfig | null {
	return config.oidc ?? null;
}
