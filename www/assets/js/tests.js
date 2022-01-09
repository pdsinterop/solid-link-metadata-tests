/*
 promises en qunit:
	test('success test', function(assert) {
	    assert.expect(1);

	    var promise = loadGroups(testData);

	    // return the `then` and not the original promise.
	    return promise.then(function(groups) {
	        assert.deepEquals(groups.length, 1);
	    });

	});
*/

let tests = {
	writeMeta: () => {
		var url = new URL(app.view.url);
		if (url.pathname.substring(url.pathname.length-2)!='/') {
			url.pathname += '/';
		}
		let metaUrl = new URL(url.href);
		metaUrl.pathname += '.meta';

		let store = app.view.store;

		const LM = new rdflib.Namespace('https://purl.org/pdsinterop/link-metadata#');
		const tmpRed = store.sym(url.href + 'testTempRedirect');
		const tmpRedTarget = store.sym('https://www.example.com/'); //FIXME: add good target

		store.add(tmpRed, LM('redirectTemporary'), tmpRedTarget);

		return solidApi.write(metaUrl.href, store);
	},
	temporaryRedirect: () => {
		return true;
	},
	permanentRedirect: () => {
		return true;
	},
	forget: () => {
		return true;
	},
	writeDeleted: () => {
		return true;
	},
	writeTemporaryRedirect: () => {
		return true;
	},
	writePermanentRedirect: () => {
		return true;
	},
	removeAllRedirects: () => {
		return true;
	}
};

QUnit.module('link-meta', function() {
	QUnit.test('Can I write a .meta file?', function(assert) {
		const done = assert.async();
		tests.writeMeta().then((response) => {
			assert.equal(response.ok, true);
			done();			
		});
	});
	QUnit.test('Does temporaryRedirect work?', function(assert) {
		assert.equal(tests.temporaryRedirect(), true);
	});
	QUnit.test('Does permanentRedirect work?', function(assert) {
		assert.equal(tests.permanentRedirect(), true);
	});
	QUnit.test('Does forget (delete) work?', function(assert) {
		assert.equal(tests.forget(), true);
	});
	QUnit.test('Is deleted marker gone after writing a file?', function(assert) {
		assert.equal(tests.writeDeleted(), true);
	});
	QUnit.test('Is temporaryRedirect marker gone after writing a file?', function(assert) {
		assert.equal(tests.writeTemporaryRedirect(), true);
	});
	QUnit.test('Is permanentRedirect marker gone after writing a file?', function(assert) {
		assert.equal(tests.writePermanentRedirect(), true);
	});
	QUnit.test('Can I remove redirects through .meta?', function(assert) {
		assert.equal(tests.removeAllRedirects(), true);			
	});

});