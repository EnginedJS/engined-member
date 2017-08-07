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
	 * @api {get} /api/v1/admin/member List members
	 * @apiName ListMembers
	 * @apiGroup Admin
	 *
	 * @apiHeader {String} authorization admin's token
	 * @apiParam {Number} perPage Number of results per page
	 * @apiParam {Number} page Page number
	 * @apiParam {Object} conditions Conditions for querying
	 *
	 * @apiSuccess {Array} Member List
	 *
	 * @apiError 404 NotFound Account doesn't exist
	 **/
	router.get('/admin/member', Permission('Admin.access'), Permission('Member.list'), async (ctx, next) => {

		const payload = ctx.request.query;

		try {
			// Getting member profile
			const members = await memberAgent
				.getMemberManager()
				.listMembers(payload.conditions, parseInt(payload.page), parseInt(payload.perPage));

			// Response
			ctx.body = members;

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
