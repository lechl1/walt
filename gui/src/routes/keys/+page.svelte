<script lang="ts">
	import { onMount } from 'svelte';
	import * as Select from '$lib/components/ui/select/index.js';
	import * as Table from '$lib/components/ui/table/index.js';
	import { Button } from '$lib/components/ui/button/index.js';
	import { Input } from '$lib/components/ui/input/index.js';
	import { Badge } from '$lib/components/ui/badge/index.js';
	import { api, connectEvents, type KeyInfo, type HostKey } from '$lib/api.js';
	import Trash2 from '@lucide/svelte/icons/trash-2';
	import KeyRound from '@lucide/svelte/icons/key-round';

	let keys = $state<KeyInfo[]>([]);
	let hostKeys = $state<HostKey[]>([]);

	let genName = $state('');
	let genType = $state('ed25519');
	let genComment = $state('');

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

	async function loadKeys() {
		keys = (await api.listKeys())?.keys ?? [];
	}
	async function loadHostKeys() {
		hostKeys = (await api.listHostKeys())?.keys ?? [];
	}

	function generate(e: Event) {
		e.preventDefault();
		const name = genName.trim();
		if (!name) return setStatus('enter a key name', 'err');
		guard(async () => {
			setStatus('generating…');
			await api.generateKey(name, genType, genComment.trim() || undefined);
			genName = '';
			genComment = '';
			setStatus(`generated ${name}`, 'ok');
			await loadKeys();
		});
	}
	function removeKey(id: string) {
		guard(async () => {
			await api.deleteKey(id);
			setStatus(`deleted ${id}`, 'ok');
			await loadKeys();
		});
	}

	onMount(() => {
		guard(async () => {
			await Promise.all([loadKeys(), loadHostKeys()]);
			setStatus('ready', 'ok');
		});
		const ws = connectEvents((m) => {
			if (m.kind === 'key') loadKeys();
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
		<h1 class="text-sm font-medium text-muted-foreground">SSH key management (this machine)</h1>
		<span
			class="ml-auto text-xs"
			class:text-green-500={statusKind === 'ok'}
			class:text-destructive={statusKind === 'err'}
			data-testid="status">{status}</span
		>
	</header>

	<section class="space-y-4">
		<h2 class="border-b pb-2 text-sm font-semibold uppercase tracking-wide text-muted-foreground">
			Managed keys
		</h2>
		<form class="flex flex-wrap items-center gap-3" onsubmit={generate}>
			<Input class="max-w-xs" placeholder="key name" bind:value={genName} data-testid="gen-name" />
			<Select.Root type="single" value={genType} onValueChange={(v) => (genType = v)}>
				<Select.Trigger class="w-36" data-testid="gen-type">{genType}</Select.Trigger>
				<Select.Content>
					<Select.Item value="ed25519" label="ed25519">ed25519</Select.Item>
					<Select.Item value="rsa" label="rsa">rsa</Select.Item>
					<Select.Item value="ecdsa" label="ecdsa">ecdsa</Select.Item>
				</Select.Content>
			</Select.Root>
			<Input class="max-w-xs" placeholder="comment (optional)" bind:value={genComment} />
			<Button type="submit" data-testid="gen-submit"><KeyRound class="size-4" /> generate</Button>
		</form>
		<Table.Root data-testid="keys-table">
			<Table.Header>
				<Table.Row>
					<Table.Head>Id</Table.Head>
					<Table.Head>Type</Table.Head>
					<Table.Head>Fingerprint</Table.Head>
					<Table.Head>Comment</Table.Head>
					<Table.Head class="text-right">Actions</Table.Head>
				</Table.Row>
			</Table.Header>
			<Table.Body>
				{#each keys as k (k.id)}
					<Table.Row>
						<Table.Cell class="font-medium">{k.id}</Table.Cell>
						<Table.Cell>{k.type}</Table.Cell>
						<Table.Cell class="font-mono text-xs text-muted-foreground">{k.fingerprint}</Table.Cell>
						<Table.Cell class="text-muted-foreground">{k.comment}</Table.Cell>
						<Table.Cell class="text-right">
							<Button variant="ghost" size="sm" onclick={() => removeKey(k.id)}>
								<Trash2 class="size-4 text-destructive" />
							</Button>
						</Table.Cell>
					</Table.Row>
				{:else}
					<Table.Row>
						<Table.Cell colspan={5} class="text-muted-foreground italic">no managed keys yet</Table.Cell>
					</Table.Row>
				{/each}
			</Table.Body>
		</Table.Root>
	</section>

	<section class="space-y-4">
		<h2 class="border-b pb-2 text-sm font-semibold uppercase tracking-wide text-muted-foreground">
			Host SSH keys (pre-existing)
		</h2>
		<Table.Root data-testid="host-keys-table">
			<Table.Header>
				<Table.Row>
					<Table.Head>Scope</Table.Head>
					<Table.Head>Owner</Table.Head>
					<Table.Head>Type</Table.Head>
					<Table.Head>Fingerprint</Table.Head>
					<Table.Head>Path</Table.Head>
				</Table.Row>
			</Table.Header>
			<Table.Body>
				{#each hostKeys as k (k.path)}
					<Table.Row>
						<Table.Cell>
							{#if k.scope === 'host'}<Badge variant="outline">host</Badge>{:else}<Badge
									variant="secondary">user</Badge
								>{/if}
						</Table.Cell>
						<Table.Cell>{k.owner}</Table.Cell>
						<Table.Cell>{k.type}</Table.Cell>
						<Table.Cell class="font-mono text-xs text-muted-foreground">{k.fingerprint}</Table.Cell>
						<Table.Cell class="font-mono text-xs text-muted-foreground">{k.path}</Table.Cell>
					</Table.Row>
				{:else}
					<Table.Row>
						<Table.Cell colspan={5} class="text-muted-foreground italic">none found</Table.Cell>
					</Table.Row>
				{/each}
			</Table.Body>
		</Table.Root>
	</section>
</div>
