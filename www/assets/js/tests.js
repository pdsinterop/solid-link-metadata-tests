var url     = null;
var store   = null;
var metaUrl = null;
var links   = {};
const LM    = new rdflib.Namespace('https://purl.org/pdsinterop/link-metadata#');

var tests = {
	setup: () => {
		url = new URL(app.view.url);

		metaUrl = new URL(url.href);
		metaUrl.pathname += '.meta';

		store = app.view.store;

		let testSource = window.location.toString();
		if (testSource.substring(testSource.length-1)!=='/') {
			testSource += '/';
		}

		// Returns a given URL with, with the given path appended.
		// Only the path is altered, keeping any port number, query-params, etc.
		function appendPath(uri, path) {
			const url = new URL(uri);

            url.pathname += path;
            console.log(url.href);
            return url.href
		}

		links.tmpRed         = store.sym(url.href + 'testTempRedirect');
		links.tmpRedTarget   = store.sym(appendPath(testSource, 'redirect-temporary.html'));
		links.permRed        = store.sym(url.href + 'testPermanentRedirect');
		links.permRedTarget  = store.sym(appendPath(testSource, 'redirect-permanent.html'));
		links.extraRed       = store.sym(url.href + 'testExtraRedirect');
		links.extraRedTarget = store.sym(appendPath(testSource, 'redirect-extra.html'));
		links.deleted        = store.sym(url.href + 'testDeleted/');
		links.forget         = store.sym(url.href + 'testForget/');
		if (!store.any(links.tmpRed, LM('redirectTemporary'))) {
			store.add(links.tmpRed, LM('redirectTemporary'), links.tmpRedTarget);
		}
		if (!store.any(links.permRed, LM('redirectPermanent'))) {
			store.add(links.permRed, LM('redirectPermanent'), links.permRedTarget);
		}
		if (!store.any(links.deleted, LM('deleted'))) {
			store.add(links.deleted, LM('deleted'), 'Because we say so');
		}
		if (!store.any(links.forget, LM('forget'))) {
			store.add(links.forget, LM('forget'), 'You have the right to be forgotten');
		}
		if (!store.any(links.extraRed, LM('redirectTemporary'))) {
			store.add(links.extraRed, LM('redirectTemporary'), links.extraRedTarget);
		}
		return solidApi.write(metaUrl.href, store)
		.catch(response => {
			if (response.status==401) {
				document.getElementById('setIssuer').setAttribute('open','open');
			}
		});
	},
	temporaryRedirect: () => {
		return solidApi.fetch(url.href + 'testTempRedirect')
		.catch(response => {
			return response;
		});
	},
	temporaryRedirectSub: () => {
		return solidApi.fetch(url.href + 'testTempRedirect/sub/')
		.catch(response => {
			return response;
		});
	},
	permanentRedirect: () => {
		return solidApi.fetch(url.href + 'testPermanentRedirect')
		.catch(response => {
			return response;
		});

	},
	permanentRedirectSub: () => {
		return solidApi.fetch(url.href + 'testPermanentRedirect/sub/')
		.catch(response => {
			return response;
		});
	},
	forget: () => {
		return solidApi.fetch(url.href + 'testForget/')
		.catch(response => {
			return response;
		});
	},
	forgetSub: () => {
		return solidApi.fetch(url.href + 'testForget/sub/')
		.catch(response => {
			return response;
		});
	},
	deleted: () => {
		return solidApi.fetch(url.href + 'testDeleted/')
		.catch(response => {
			return response;
		});
	},
	deletedSub: () => {
		return solidApi.fetch(url.href + 'testDeleted/sub/')
		.catch(response => {
			return response;
		});
	},
	writeDeleted: () => {
		return solidApi.write(url.href + 'testDeleted', 'no longer deleted', 'text/plain')
		.then(response => {
			if (response.ok) {
				return solidApi.fetch(url.href+'testDeleted');
			}
		});
	},
	writeForget: () => {
		return solidApi.write(url.href + 'testForget', 'no longer forgotten', 'text/plain')
		.then(response => {
			if (response.ok) {
				return solidApi.fetch(url.href+'testForget');
			}
		});
	},
	writeTemporaryRedirect: () => {
		return solidApi.write(url.href + 'testTemporaryRedirect', 'no longer redirected temporary', 'text/plain')
		.then(response => {
			if (response.ok) {
				return solidApi.fetch(url.href+'testTemporaryRedirect');
			}
		});
	},
	writePermanentRedirect: () => {
		return solidApi.write(url.href + 'testPermanentRedirect', 'no longer redirected permanently', 'text/plain')
		.then(response => {
			if (response.ok) {
				return solidApi.fetch(url.href+'testPermanentRedirect');
			}
		});
	},
	removeAllRedirects: () => {
		return solidApi.write(metaUrl.href, app.view.text)
		.then((response) => {
			if (response.ok) {
				return solidApi.fetch(url.href+'testExtraRedirect');
			}
			throw response;
		})
		.catch(response => {
			if (response.status==404) {
				return true;
			}
			return response;
		});
	},
	teardown: () => {
		return Promise.all([
			solidApi.delete(url.href+'testDeleted'),
			solidApi.delete(url.href+'testForget'),
			solidApi.delete(url.href+'testTemporaryRedirect'),
			solidApi.delete(url.href+'testPermanentRedirect')
		]).catch(response => {
            if (response.status > 399) {
                throw 'Could not delete test data' + response.statusText;
            }
        });
	}

};

QUnit.module('link-meta', function() {
	QUnit.test('Does temporaryRedirect work?', function(assert) {
		const done = assert.async();
		tests.temporaryRedirect().then((result) => {
            assert.true(result.text && result.text.includes('Redirect Temporary Target'), true);
			done();
		});
	});
	QUnit.test('Does permanentRedirect work?', function(assert) {
		const done = assert.async();
		tests.permanentRedirect().then((result) => {
			assert.true(result.text && result.text.includes('Redirect Permanent Target'), true);
			done();
		});
	});
	QUnit.test('Does delete work?', function(assert) {
		const done = assert.async();
		tests.deleted().then((response) => {
			assert.equal(response.status || 200, 404);
			done();
		});
	});
	QUnit.test('Does forget work?', function(assert) {
		const done = assert.async();
		tests.forget().then((response) => {
			assert.equal(response.status || 200, 410);
			done();
		});
	});
	QUnit.test('Is deleted marker gone after writing a file?', function(assert) {
		const done = assert.async();
		tests.writeDeleted().then((result) => {
			assert.equal(result.text, 'no longer deleted');
			done();
		}).catch(response => {
			assert.equal(response.status, 200);
			done();
		});
	});
	QUnit.test('Is forget marker gone after writing a file?', function(assert) {
		const done = assert.async();
		tests.writeForget().then((result) => {
			assert.equal(result.text, 'no longer forgotten');
			done();
		}).catch(response => {
			assert.equal(response.status, 200);
			done();
		});
	});
	QUnit.test('Is temporaryRedirect marker gone after writing a file?', function(assert) {
		const done = assert.async();
		tests.writeTemporaryRedirect().then((result) => {
			assert.equal(result.text, 'no longer redirected temporary');
			done();
		}).catch(response => {
			assert.equal(response.status, 200);
			done();
		});
	});
	QUnit.test('Is permanentRedirect marker gone after writing a file?', function(assert) {
		const done = assert.async();
		tests.writePermanentRedirect().then((result) => {
			assert.equal(result.text, 'no longer redirected permanently');
			done();
		}).catch(response => {
			assert.equal(response.status, 200);
			done();
		});
	});
	QUnit.test('Can I remove redirects through .meta?', function(assert) {
		const done = assert.async();
		tests.removeAllRedirects().then((result) => {
			assert.equal(result, true);
			done();
		});
	});
	QUnit.done(function() {
		tests.teardown();
	});
});
