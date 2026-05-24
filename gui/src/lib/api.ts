// Typed client for the waltd REST + WS API. The shapes here mirror the
// contract in modules/walt/openapi.yaml (REST) and asyncapi.yaml (WS events).
// The GUI is served by waltd itself, so all calls are same-origin (relative).

export interface Project {
	name: string;
	environments: string[];
}
export interface EnvInfo {
	name: string;
	file_count: number;
	has_password: boolean;
}
export interface FileInfo {
	name: string;
	encrypted: boolean;
	size: number;
}
export interface FileContent {
	name: string;
	content: string;
	encrypted: boolean;
}

/** A managed SSH keypair. */
export interface KeyInfo {
	id: string;
	type: string;
	fingerprint: string;
	comment: string;
	public_key: string;
}
/** A pre-existing SSH key found on the host (not walt-managed). */
export interface HostKey {
	scope: 'user' | 'host';
	owner: string;
	path: string;
	type: string;
	fingerprint: string;
	comment: string;
	public_key: string;
}
/** A mutation event broadcast on /ws/events (see asyncapi.yaml). */
export interface WaltEvent {
	kind: 'project' | 'env' | 'file' | 'key' | 'authorized';
	op: string;
	project?: string;
	env?: string;
	file?: string;
	count?: number;
	id?: string;
	user?: string;
}

const enc = encodeURIComponent;

async function req<T>(path: string, init?: RequestInit): Promise<T | null> {
	const r = await fetch(path, init);
	if (!r.ok && r.status !== 204) {
		const body = await r.text().catch(() => '');
		throw new Error(`${path} → ${r.status} ${body}`.trim());
	}
	return r.status === 204 ? null : ((await r.json().catch(() => null)) as T | null);
}

function body(value: unknown): RequestInit {
	return { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(value) };
}
const envPath = (p: string, e: string) => `/api/projects/${enc(p)}/envs/${enc(e)}`;

export const api = {
	listProjects: () => req<{ projects: Project[] }>('/api/projects'),

	createProject: (name: string, environments: string[]) =>
		req('/api/projects', body({ name, environments })),

	listEnvs: (project: string) =>
		req<{ environments: EnvInfo[] }>(`/api/projects/${enc(project)}/envs`),

	createEnv: (project: string, name: string) =>
		req(`/api/projects/${enc(project)}/envs`, body({ name })),

	listFiles: (project: string, env: string) =>
		req<{ files: FileInfo[] }>(`${envPath(project, env)}/files`),

	getFile: (project: string, env: string, file: string) =>
		req<FileContent>(`${envPath(project, env)}/files/${enc(file)}`),

	addFile: (project: string, env: string, name: string, content: string) =>
		req(`${envPath(project, env)}/files`, body({ name, content })),

	putFile: (project: string, env: string, file: string, content: string) =>
		req(`${envPath(project, env)}/files/${enc(file)}`, {
			...body({ content }),
			method: 'PUT'
		}),

	deleteFile: (project: string, env: string, file: string) =>
		req(`${envPath(project, env)}/files/${enc(file)}`, { method: 'DELETE' }),

	encryptAll: (project: string, env: string) => req(`${envPath(project, env)}/encrypt`, body({})),
	decryptAll: (project: string, env: string) => req(`${envPath(project, env)}/decrypt`, body({})),

	// --- ssh keys (merged from arthur) ---
	listKeys: () => req<{ keys: KeyInfo[] }>('/api/keys'),
	generateKey: (name: string, type: string, comment?: string) =>
		req('/api/keys', body({ name, type, comment })),
	deleteKey: (id: string) => req(`/api/keys/${enc(id)}`, { method: 'DELETE' }),
	listHostKeys: () => req<{ keys: HostKey[] }>('/api/host-keys')
};

/** Subscribe to live vault-mutation events. Returns the socket (or null). */
export function connectEvents(onEvent: (e: WaltEvent) => void): WebSocket | null {
	try {
		const proto = location.protocol === 'https:' ? 'wss' : 'ws';
		const ws = new WebSocket(`${proto}://${location.host}/ws/events`);
		ws.onmessage = (ev) => {
			try {
				onEvent(JSON.parse(ev.data));
			} catch {
				/* ignore malformed frames */
			}
		};
		return ws;
	} catch {
		return null;
	}
}
