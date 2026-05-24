<script lang="ts">
	import './layout.css';
	import favicon from '$lib/assets/favicon.svg';
	import { page } from '$app/state';

	let { children } = $props();

	const tabs = [
		{ href: '/', label: 'Vault', testid: 'tab-vault' },
		{ href: '/keys', label: 'SSH Keys', testid: 'tab-keys' }
	];
	const isActive = (href: string) =>
		href === '/' ? page.url.pathname === '/' : page.url.pathname.startsWith(href);
</script>

<svelte:head><link rel="icon" href={favicon} /></svelte:head>

<div class="min-h-screen bg-background text-foreground">
	<nav class="flex items-center gap-1 border-b px-6 pt-3" data-testid="tabbar">
		<span class="mr-4 text-lg font-semibold tracking-tight text-primary" data-testid="title">walt</span>
		{#each tabs as t (t.href)}
			<a
				href={t.href}
				data-testid={t.testid}
				aria-current={isActive(t.href) ? 'page' : undefined}
				class="border-b-2 px-3 pb-2 text-sm transition-colors {isActive(t.href)
					? 'border-primary text-foreground'
					: 'border-transparent text-muted-foreground hover:text-foreground'}"
			>
				{t.label}
			</a>
		{/each}
	</nav>
	{@render children()}
</div>
