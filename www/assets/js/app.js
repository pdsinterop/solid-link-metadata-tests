if (window.location.protocol != 'https:') {
	window.location.protocol = 'https:';
}

QUnit.config.autostart = false;

const getDefaultSession = solidAuthn.getDefaultSession;
const Parser = n3.Parser;
const Writer = n3.Writer;
let rawstring = '';
let rawdata = null;

const app = simply.app({
	routes: {
	},
    commands: {
		'testServer': (form,values) => {
			app.actions.afterLogin(values.url);
		},
        'login': (form, values) => {
            document.getElementById('setIssuer').removeAttribute('open');
            return app.actions.connect(values.issuer, app.view.url)
            .then(() => {
				console.log('test '+app.view.url);	
			});
		},
		'logout': (el, value) => {
			app.actions.disconnect()
			.then(() => {
				window.location.reload();
//				document.getElementById('testServerDialog').setAttribute('open','open');
			});
		}
    },
    actions: {
        connect: (issuer,url) => solidApi.connect(issuer,url),
        disconnect: () => solidApi.disconnect(),
        afterLogin: (url) => {
			app.actions.testServer(url)
			.then(() => {
	            document.getElementById('testServerDialog').removeAttribute('open');
	            app.actions.runtests();
			})
			.catch(error => {
				if (error.status===401) {
                    document.getElementById('testServerDialog').removeAttribute('open');
					document.getElementById('setIssuer').setAttribute('open','open');
//					app.view.url = values.url;
				} else {
					alert(error.message);
				}
			});
		},
		testServer: (url) => {
			var url = new URL(url);
			if (url.pathname.substring(url.pathname.length-2)!='/') {
				url.pathname += '/';
			}
			app.view.url = url.href;
			url.pathname += '.meta';
			return solidApi.fetch(url.href)
			.then(result => {
				app.view.store = result.store;
				app.view.text  = result.text;
			});
/*			.then(store => {
				rawdata = store;
				solidApi.write(url.href, store);
			});
*/
		},
		runtests: function() {
			tests.setup().then(() => {
				QUnit.start();
			})
			.catch(e => {
				alert(e);
			});
		}
    },
    view: {
    }
});

const solidSession = getDefaultSession();

const prefixes = {};

const solidSupported = ['text/turtle','application/trig','application/n-quads','application/n-triples','text/n3', 'application/json', 'application/ld+json', 'application/rdf+xml', 'text/html', 'application/xhtml+xml', 'image/svg+xml','application/xml'];

const solidApi = {
    fetch: function(url) {
        const parser = new Parser({blankNodePrefix: '', baseIRI: url});
		var fetchParams = {
			mode: 'cors',
			headers: {
				'Accept': 'application/*'
			}
		};
		var contentType = '';
		return solidSession.fetch(url).then(response => {
			if (response.ok) {
				contentType = response.headers.get('Content-Type');
				return response.text();
			} else {
                throw response;
			}
		})
        .then(text => {
        	if (solidSupported.includes(contentType)) {
	        	let store = rdflib.graph();
				rdflib.parse(text, store, url, contentType);
				return { store: store, text: text };
			} else {
				return { text: text };
			}
		});
    },
    write: function(url, store, contentType='text/turtle') {
    	if (typeof store !== 'string' && solidSupported.includes(contentType)) {
	    	var body = rdflib.serialize(null, store, url, contentType);
	    } else {
	    	var body = store;
	    }
    	console.log(store);
    	var fetchParams = {
    		headers: {
    			'Content-Type': contentType
    		},
    		body: store,
    		method: 'PUT'
    	}
    	return solidSession.fetch(url, fetchParams).then(response => {
    		if (response.ok) {
    			return response;
    		} else {
    			throw response;
    		}
    	});
    },
    delete: function(url) {
    	var fetchParams = {
    		method: 'DELETE'
    	}
    	return solidSession.fetch(url, fetchParams).then(response => {
    		if (response.ok) {
    			return response;
    		} else {
    			throw response;
    		}
    	});
    },
    connect: function(issuer, resourceUrl) {
        if (solidSession.info && solidSession.info.isLoggedIn === false) {
            let url = new URL(window.location);
            url.searchParams.set('resourceUrl', resourceUrl);
            return solidSession.login({
                oidcIssuer: issuer,
                redirectUrl: url.href
            });
        }
        return solidSession.info
    },
    disconnect: function() {
        return solidSession.logout();
    },
    getPodUrl: function(webIdUrl) {
        return solidApi.fetch(webIdUrl.href)
            .then(quads => quads.find(quad => quad.predicate.value.includes('pim/space#storage')).object.value)
            .then(podUrl => {
                if ( ! podUrl.endsWith('/')) {
                    podUrl += '/'
                }
                return podUrl
            });
    }
};

window.app = app;
window.solidApi = solidApi;
window.solidSession = solidSession;

solidSession.handleIncomingRedirect({url: window.location.href, restorePreviousSession: true})
.then(() => {
    let search = new URLSearchParams(window.location.search);
    if (search.has('resourceUrl') && solidSession.info && solidSession.info.isLoggedIn) {
        let resourceUrl = search.get('resourceUrl');
        localStorage.setItem('resourceUrl',resourceUrl);
        if (resourceUrl) {
            history.replaceState({}, window.title, window.location.pathname);
        	app.actions.afterLogin(resourceUrl);
        }
    }
});


