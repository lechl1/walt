<script lang="ts">
	// CodeMirror 6 editor, bundled locally by Vite (no CDN). Mount one per file
	// via {#key} so each open starts a fresh document; read the buffer with the
	// exported value() on save.
	import { EditorView, basicSetup } from 'codemirror';
	import { EditorState } from '@codemirror/state';
	import { yaml } from '@codemirror/lang-yaml';
	import { oneDark } from '@codemirror/theme-one-dark';

	let { doc = '' }: { doc?: string } = $props();

	let host = $state<HTMLDivElement>();
	let view: EditorView | null = null;

	$effect(() => {
		if (!host) return;
		view = new EditorView({
			state: EditorState.create({
				doc,
				extensions: [basicSetup, yaml(), oneDark, EditorView.lineWrapping]
			}),
			parent: host
		});
		return () => {
			view?.destroy();
			view = null;
		};
	});

	/** Current buffer contents (read on save). */
	export function value(): string {
		return view ? view.state.doc.toString() : doc;
	}
</script>

<div bind:this={host} class="cm-host overflow-hidden rounded-md border text-sm" data-testid="editor-host"></div>

<style>
	:global(.cm-host .cm-editor) {
		height: 420px;
	}
	:global(.cm-host .cm-scroller) {
		font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
	}
</style>
