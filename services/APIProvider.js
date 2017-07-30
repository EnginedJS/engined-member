const { RouterService } = require('engined-http');
const {
	General,
	Member
} = require('../apis');

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
		applyRouter(router, General(this));
		applyRouter(router, Member(this));

		return router;
	}
};
