<script lang="ts">
	import { onMount } from 'svelte';
	import * as Select from '$lib/components/ui/select/index.js';
	import * as Table from '$lib/components/ui/table/index.js';
	import { Button } from '$lib/components/ui/button/index.js';
	import { Input } from '$lib/components/ui/input/index.js';
	import { Badge } from '$lib/components/ui/badge/index.js';
	import Editor from '$lib/components/Editor.svelte';
	import { api, connectEvents, type Project, type EnvInfo, type FileInfo } from '$lib/api.js';
	import Lock from '@lucide/svelte/icons/lock';
	import LockOpen from '@lucide/svelte/icons/lock-open';
	import Trash2 from '@lucide/svelte/icons/trash-2';
	import FilePlus from '@lucide/svelte/icons/file-plus';
	import Save from '@lucide/svelte/icons/save';
	import X from '@lucide/svelte/icons/x';

	let projects = $state<Project[]>([]);
	let project = $state('');
	let envs = $state<EnvInfo[]>([]);
	let env = $state('');
	let files = $state<FileInfo[]>([]);
	let newFileName = $state('');
	let editing = $state<{ file: string; isNew: boolean; doc: string } | null>(null);
	let editorRef = $state<{ value: () => string }>();

	let status = $state('connecting…');
	let statusKind = $state<'ok' | 'err' | ''>('');
	function setStatus(text: string, kind: 'ok' | 'err' | '' = '') {
		status = text;
		statusKind = kind;
	}
	async function guard(fn: () => Promise<void>) {
		try {
			await fn();
		} catch (e) {
			setStatus(String(e instanceof Error ? e.message : e), 'err');
		}
	}

	async function loadProjects(select?: string) {
		const data = await api.listProjects();
		projects = data?.projects ?? [];
		const want = select ?? project;
		project = projects.some((p) => p.name === want) ? want : (projects[0]?.name ?? '');
		await loadEnvs();
	}
	async function loadEnvs(select?: string) {
		if (!project) {
			envs = [];
			env = '';
			files = [];
			return;
		}
		const data = await api.listEnvs(project);
		envs = data?.environments ?? [];
		const want = select ?? env;
		env = envs.some((e) => e.name === want) ? want : (envs[0]?.name ?? '');
		await loadFiles();
	}
	async function loadFiles() {
		if (!project || !env) {
			files = [];
			return;
		}
		const data = await api.listFiles(project, env);
		files = data?.files ?? [];
	}

	function selectProject(v: string) {
		project = v;
		env = '';
		editing = null;
		guard(() => loadEnvs());
	}
	function selectEnv(v: string) {
		env = v;
		editing = null;
		guard(() => loadFiles());
	}

	function newProject() {
		const name = window.prompt('New project name:');
		if (!name) return;
		const environments = (window.prompt('Environments (comma-separated):', 'dev,test,prod') ?? '')
			.split(',')
			.map((s) => s.trim())
			.filter(Boolean);
		guard(async () => {
			await api.createProject(name, environments);
			setStatus(`created project ${name}`, 'ok');
			await loadProjects(name);
		});
	}
	function newEnv() {
		if (!project) return setStatus('select a project first', 'err');
		const name = window.prompt('New environment name:');
		if (!name) return;
		guard(async () => {
			await api.createEnv(project, name);
			setStatus(`created environment ${name}`, 'ok');
			await loadEnvs(name);
		});
	}

	function startNewFile() {
		if (!project || !env) return setStatus('select a project and environment', 'err');
		const name = newFileName.trim();
		if (!name) return setStatus('enter a file name', 'err');
		newFileName = '';
		editing = { file: name, isNew: true, doc: '' };
		setStatus(`new file ${name} — add content and save`, 'ok');
	}
	function editFile(file: string) {
		guard(async () => {
			setStatus('decrypting…');
			const data = await api.getFile(project, env, file);
			editing = { file, isNew: false, doc: data?.content ?? '' };
			setStatus(`editing ${file}`, 'ok');
		});
	}
	function save() {
		if (!editing) return;
		const content = editorRef?.value() ?? editing.doc;
		const { file, isNew } = editing;
		guard(async () => {
			setStatus('encrypting & saving…');
			if (isNew) await api.addFile(project, env, file, content);
			else await api.putFile(project, env, file, content);
			editing = null;
			setStatus(`saved & encrypted ${file}`, 'ok');
			await loadFiles();
		});
	}
	function del(file: string) {
		guard(async () => {
			await api.deleteFile(project, env, file);
			if (editing?.file === file) editing = null;
			setStatus(`deleted ${file}`, 'ok');
			await loadFiles();
		});
	}
	function bulk(which: 'encrypt' | 'decrypt') {
		if (!project || !env) return setStatus('select a project and environment', 'err');
		guard(async () => {
			setStatus(`${which}ing…`);
			if (which === 'encrypt') await api.encryptAll(project, env);
			else await api.decryptAll(project, env);
			setStatus(`${which}ed all files`, 'ok');
			await loadFiles();
		});
	}

	onMount(() => {
		guard(async () => {
			await loadProjects();
			setStatus('ready', 'ok');
		});
		const ws = connectEvents((m) => {
			if (m.kind === 'project' || m.kind === 'env') loadProjects(project);
			else if (m.kind === 'file' && m.project === project && m.env === env) loadFiles();
		});
		if (ws) {
			ws.onopen = () => setStatus('live', 'ok');
			ws.onclose = () => setStatus('disconnected');
		}
		return () => ws?.close();
	});
</script>

<div class="mx-auto max-w-5xl space-y-6 p-6">
	<header class="flex items-baseline gap-3">
		<h1 class="text-sm font-medium text-muted-foreground">ansible-vault file manager</h1>
		<span
			class="ml-auto text-xs"
			class:text-green-500={statusKind === 'ok'}
			class:text-destructive={statusKind === 'err'}
			data-testid="status">{status}</span
		>
	</header>

	<section class="space-y-4">
		<div>
			<h2 class="border-b pb-2 text-sm font-semibold uppercase tracking-wide text-muted-foreground">
				Vault
			</h2>
			<p class="pt-1 text-xs text-muted-foreground">
				Pick a project and environment, then manage its files.
			</p>
		</div>
		<div class="flex flex-wrap items-center gap-3">
			<Select.Root type="single" value={project} onValueChange={selectProject}>
				<Select.Trigger class="w-44" data-testid="project-sel">
					{project || 'select project'}
				</Select.Trigger>
				<Select.Content>
					{#each projects as p (p.name)}
						<Select.Item value={p.name} label={p.name}>{p.name}</Select.Item>
					{/each}
				</Select.Content>
			</Select.Root>

			<Select.Root type="single" value={env} onValueChange={selectEnv}>
				<Select.Trigger class="w-44" data-testid="env-sel">
					{env || 'select environment'}
				</Select.Trigger>
				<Select.Content>
					{#each envs as e (e.name)}
						<Select.Item value={e.name} label={e.name}>{e.name} ({e.file_count})</Select.Item>
					{/each}
				</Select.Content>
			</Select.Root>

			<Button variant="outline" onclick={newProject} data-testid="new-project">+ project</Button>
			<Button variant="outline" onclick={newEnv} data-testid="new-env">+ environment</Button>
		</div>
	</section>

	<section class="space-y-4">
		<div>
			<h2 class="border-b pb-2 text-sm font-semibold uppercase tracking-wide text-muted-foreground">
				Files
			</h2>
			<p class="pt-1 text-xs text-muted-foreground">
				Add, edit, and encrypt files in the selected environment.
			</p>
		</div>
		<div class="space-y-4">
			<div class="flex flex-wrap items-center gap-3">
				<Input
					class="max-w-xs"
					placeholder="new file name (e.g. secrets.env)"
					bind:value={newFileName}
					data-testid="add-name"
				/>
				<Button onclick={startNewFile} data-testid="add-file">
					<FilePlus class="size-4" /> add file
				</Button>
				<div class="ml-auto flex gap-2">
					<Button variant="outline" onclick={() => bulk('encrypt')} data-testid="encrypt-all">
						encrypt all
					</Button>
					<Button variant="outline" onclick={() => bulk('decrypt')} data-testid="decrypt-all">
						decrypt all
					</Button>
				</div>
			</div>

			<Table.Root data-testid="files-table">
				<Table.Header>
					<Table.Row>
						<Table.Head>File</Table.Head>
						<Table.Head>State</Table.Head>
						<Table.Head>Size</Table.Head>
						<Table.Head class="text-right">Actions</Table.Head>
					</Table.Row>
				</Table.Header>
				<Table.Body>
					{#each files as f (f.name)}
						<Table.Row>
							<Table.Cell class="font-medium">{f.name}</Table.Cell>
							<Table.Cell>
								{#if f.encrypted}
									<Badge variant="secondary"><Lock class="size-3" /> encrypted</Badge>
								{:else}
									<Badge variant="outline"><LockOpen class="size-3" /> plaintext</Badge>
								{/if}
							</Table.Cell>
							<Table.Cell class="text-muted-foreground">{f.size}</Table.Cell>
							<Table.Cell class="space-x-2 text-right">
								<Button variant="outline" size="sm" onclick={() => editFile(f.name)}>edit</Button>
								<Button variant="ghost" size="sm" onclick={() => del(f.name)}>
									<Trash2 class="size-4 text-destructive" />
								</Button>
							</Table.Cell>
						</Table.Row>
					{:else}
						<Table.Row>
							<Table.Cell colspan={4} class="text-muted-foreground italic">
								{project && env ? 'no files in this environment' : 'select a project and environment'}
							</Table.Cell>
						</Table.Row>
					{/each}
				</Table.Body>
			</Table.Root>
		</div>
	</section>

	{#if editing}
		<section class="space-y-4" data-testid="editor-section">
			<div class="flex flex-row items-center justify-between border-b pb-2">
				<h2 class="font-mono text-sm text-foreground">
					{project}/{env}/{editing.file}
				</h2>
				<div class="flex gap-2">
					<Button size="sm" onclick={save} data-testid="editor-save">
						<Save class="size-4" /> save &amp; encrypt
					</Button>
					<Button
						size="sm"
						variant="ghost"
						onclick={() => (editing = null)}
						data-testid="editor-cancel"
					>
						<X class="size-4" /> cancel
					</Button>
				</div>
			</div>
			{#key project + '/' + env + '/' + editing.file}
				<Editor bind:this={editorRef} doc={editing.doc} />
			{/key}
		</section>
	{/if}
</div>
