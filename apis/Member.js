const RestPack = require('restpack');

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

	/*
	 * @api {get} /api/v1/members/profile Getting users profile
	 * @apiName GetMemberProfile
	 * @apiGroup Member
	 *
	 * @apiHeader {String} authorization users token
	 *
	 * @apiSuccess {Object} Member information
	 * @apiError 400 {String} BadRequest
	 * @apiError 403 {String} Disabled Account is disabled
	 * @apiError 404 {String} NotFound Account doesn't exist
	 */
	router.get('/members/profile', Permission('Member.access'), async (ctx, next) => {

		// Create a package for restful API
		let pkg = new RestPack();

		try {
			// Verify member account
			let member = await memberAgent.getMemberManager().getProfile(ctx.state.session.id);

			// Prepare JWT package for user
			pkg
				.setData(member)
				.sendKoa(ctx);

		} catch(e) {

			switch(e.name) {
			case 'NotExist':
				ctx.throw(404);
			}

			console.error(e);
		}
	});

	/*
	 * @api {put} /api/v1/members/password Getting users profile
	 * @apiName GetMemberProfile
	 * @apiGroup Member
	 *
	 * @apiHeader {String} authorization users token
	 * @apiParam {String} old Old password
	 * @apiParam {String} new New password
	 *
	 * @apiError 400 {String} BadRequest
	 * @apiError 401 {String} IncorrectPassword Old password is incorrect
	 * @apiError 403 {String} Disabled Account is disabled
	 * @apiError 404 {String} NotFound Account doesn't exist
	 */
	router.put('/members/password', Permission('Member.access'), async (ctx, next) => {

		// Create a package for restful API
		let pkg = new RestPack();

		if (!ctx.request.body) {
			return pkg.setStatus(RestPack.Status.BadRequest).sendKoa(ctx);
		}

		let payload = ctx.request.body;

		// Check parameters
		if (payload['old'] === undefined || payload['new'] === undefined) {
			return pkg.setStatus(RestPack.Status.BadRequest).sendKoa(ctx);
		}

		try {
			// Verify member account
			await memberAgent.getMemberManager().changePassword(ctx.state.session.id, payload['old'], payload['new']);

			// Prepare JWT package for user
			pkg
				.setData({
					message: 'Success'
				})
				.sendKoa(ctx);

		} catch(e) {

			switch(e.name) {
			case 'IncorrectOldPassword':
				pkg
					.setData({
						status: 401,
						message: 'Incorrect Old Password'
					})
					.sendKoa(ctx);

				break;
			case 'Disabled':
				pkg.setStatus(RestPack.Status.AccountBlocked).sendKoa(ctx);
				break;

			case 'NotExist':
				pkg.setStatus(RestPack.Status.NotFound).sendKoa(ctx);
				break;
			}

			console.error(e);
		}
	});

	return router;
};
