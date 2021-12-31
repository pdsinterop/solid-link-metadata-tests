let hyperPages = (function(global) {
	var pages = [];
	var incomingPage = '';
	return {
		goto: function(path) {
			if (!global.editor || !global.editor.currentData) {
				global.setTimeout(function() { hyperPages.goto(path); }, 100);
			} else {
				editor.transformers['hyper-page'] = {
					render: function(page) {
						if (page == path) {
							this.dataset.hyper = 'incoming';
						} else {
							this.dataset.hyper = 'outgoing';
						}
						return page;
					}
				};
				pages.forEach(page => {
					let path = page['data-simply-path'];
					Object.keys(page).forEach(prop => {
						if (prop == 'data-hyper') {
							return;
						}
						editor.currentData[path][prop] = page[prop];
					});
				});
				let page = Object.assign({}, {
						'data-simply-path': path,
						'data-simply-template': 'default',
						'data-hyper':'incoming'
					},
					global.editor.currentData[path]
				);
				if (pages.length) {
					let lastPage = pages[pages.length-1];
					delete lastPage.page;
					pages = [ Object.assign({}, lastPage, { 'data-hyper':'outgoing' }), page ];
				} else {
					pages = [ page ];
				}
				global.editor.addDataSource('hyper-pages', {
					load: function(el, callback) {
						console.log('pages',pages);
						callback(pages);
					}
				});
				global.document.querySelectorAll('[data-simply-data="hyper-pages"]').forEach(function(list) {
           			global.editor.list.applyDataSource(list, 'hyper-pages');
        		});
			}
		}
	}
})(this);
