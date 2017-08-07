const { RouterService } = require('engined-http');
const apis = require('../apis/admin');

const applyRouter = (router, subRouter) => {
	router.use(subRouter.routes(), subRouter.allowedMethods());
};

module.exports = (opts) => class extends RouterService() {

	constructor(context) {
		super(context);

		this.memberAgent = opts.memberAgent || 'default';
	}

	async setupRoutes() {

		let router = this.createRouter();

		// Apply all routers
		Object.values(apis).forEach((api) => {
			applyRouter(router, api(this));
		});

		return router;
	}
};
