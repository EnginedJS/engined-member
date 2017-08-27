const { RouterService } = require('engined-http');
const generalApis = require('../apis');
const adminApis = require('../apis/admin');

const applyRouter = (router, subRouter) => {
	router.use(subRouter.routes(), subRouter.allowedMethods());
};

module.exports = (opts) => class extends RouterService() {

	constructor(context) {
		super(context);

		this.dependencies = [
			'HTTP',
			'Member'
		];
		this.applyRouters = opts.applyRouters || [
			'general',
			'admin'
		];
		this.memberAgent = opts.memberAgent || 'default';
	}

	async initialize() {

		let agent = this.getContext().get('Member').getAgent(this.memberAgent);

		agent.initializeHTTPMiddleware();
	}

	async setupRoutes() {

		let router = this.createRouter();

		// Apply all routers
		if (this.applyRouters.includes('general')) {
			Object.values(generalApis).forEach((api) => {
				applyRouter(router, api(this));
			});
		}

		if (this.applyRouters.includes('admin')) {
			Object.values(adminApis).forEach((api) => {
				applyRouter(router, api(this));
			});
		}

		return router;
	}
};
