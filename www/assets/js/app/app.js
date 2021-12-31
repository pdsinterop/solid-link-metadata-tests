
let simplyApp = simply.app({
	routes: {
	},
	commands: {
	},
	keyboard: {
		default: {
		}
	},
	view: {
	}
});

document.addEventListener('simply-content-loaded', function() {
	hyperPages.goto('/');
});

function waitForTemplates(callback) {
	if (!document.getElementById('default')) {
		window.setTimeout(function() { waitForTemplates(callback) }, 100);
	} else {
		callback();
	}
}

waitForTemplates(function() {
	var script = document.createElement('script');
	script.setAttribute('src','//cdn.simplyedit.io/1/simply-edit.js');
	script.setAttribute('data-api-key','muze');
	script.setAttribute('data-simply-settings','seSettings');
	script.setAttribute('data-simply-images','/img/');
	script.setAttribute('data-simply-files','/files/');
	script.setAttribute('data-storage-get-post-only',1);
	document.body.appendChild(script);
});