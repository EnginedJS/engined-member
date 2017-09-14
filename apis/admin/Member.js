const mime = require('mime');

module.exports = (service) => {

	// Getting member system agent
	const memberAgent = service.getContext().get('Member').getAgent(service.memberAgent);
	const Permission = memberAgent.getPermissionMiddleware();

	// Create a new router
	let router = service.createRouter({
		prefix: '/api/v1'
	});

	// Set type to "API" for router
	router.use(service.routeType('API'));

	/**
	 * @api {get} /api/v1/admin/members List members
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
	router.get('/admin/members', Permission('Admin.access'), Permission('Member.list'), async (ctx, next) => {

		const payload = {
			page: parseInt(ctx.request.query.page) || 1,
			perPage: parseInt(ctx.request.query.perPage) || 50,
			conditions: ctx.request.query.conditions || {}
		};

		try {
			const memberManager = memberAgent.getMemberManager();

			// Count
			const total = await memberManager.countMembers(payload.conditions);

			// Getting member list
			const members = await memberManager
				.listMembers(payload.conditions, parseInt(payload.page), parseInt(payload.perPage));

			// Response
			ctx.body = {
				meta: {
					total: total,
					page: payload.page,
					perPage: payload.perPage
				},
				data: members
			};

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
