const mime = require('mime');

module.exports = (service) => {

	// Getting member system agent
	const memberAgent = service.getContext().get('Member')[service.memberAgent];
	const Permission = memberAgent.getPermissionMiddleware();

	// Create a new router
	let router = service.createRouter({
		prefix: '/api/v1'
	});

	// Set type to "API" for router
	router.use(service.routeType('API'));

	/**
	 * @api {get} /api/v1/admin/member/:memberId Getting member profile
	 * @apiName GetMemberProfile
	 * @apiGroup Admin
	 *
	 * @apiHeader {String} authorization admin's token
	 *
	 * @apiSuccess {Object} Member information
	 *
	 * @apiError 404 NotFound Account doesn't exist
	 **/
	router.get('/admin/member/:memberId', Permission('Admin.access'), Permission('Member.list'), async (ctx, next) => {
	//router.get('/admin/member/:memberId', Permission('Member.access'), async (ctx, next) => {

		try {
			// Getting member profile
			const member = await memberAgent
				.getMemberManager()
				.getFullProfile(ctx.params.memberId);

			// Response
			ctx.body = member;

		} catch(e) {

			switch(e.name) {
			case 'NotExist':
				ctx.throw(404, {
					code: 'NotExist',
					message: 'Account doesn\'t exist'
				});
			}

			throw e;
		}
	});

	return router;
};
