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

	/**
	 * @api {get} /api/v1/members/profile Getting profile
	 * @apiName GetMemberProfile
	 * @apiGroup Member
	 *
	 * @apiHeader {String} authorization user's token
	 *
	 * @apiSuccess {Object} Member information
	 *
	 * @apiError 403 Account is disabled
	 * @apiError 404 NotFound Account doesn't exist
	 **/
	router.get('/members/profile', Permission('Member.access'), async (ctx, next) => {

		try {
			// Verify member account
			const member = await memberAgent
				.getMemberManager()
				.getProfile(ctx.state.session.id);

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

	/*
	 * @api {put} /api/v1/members/profile Update member's profile
	 * @apiName UpdateMemberProfile
	 * @apiGroup Member
	 *
	 * @apiHeader {String} authorization user's token
	 *
	 * @apiSuccess {Object} Member information
	 *
	 * @apiError 403 Account is disabled
	 * @apiError 404 Account doesn't exist
	 */
	router.put('/members/profile', Permission('Member.access'), async (ctx, next) => {

		let payload = ctx.request.body;

		try {
			// Update member's profile
			let member = await memberAgent.getMemberManager().updateProfile(ctx.state.session.id, payload);

			// Response
			ctx.body = member;

		} catch(e) {

			switch(e.name) {
			case 'NotExist':
				ctx.throw(404, {
					code: 'NotExist',
					message: 'Account doesn\'t exist'
				});
			case 'ValidationFailed':
				ctx.throw(422, {
					code: 'ValidationFailed',
					message: 'Validation failed',
					errors: e.errors.map((error) => {
						switch(error.type) {
						case 'any.required':
							return {
								field: error.field,
								code: 'required'
							};

						default:
							return {
								field: error.field,
								code: 'invalid'
							};
						}
					})
				});
			}

			throw e;
		}
	});

	/**
	 * @api {put} /api/v1/members/password Change password
	 * @apiName ChangePassword
	 * @apiGroup Member
	 *
	 * @apiHeader {String} Authorization User's token
	 *
	 * @apiParam {String} old Old password
	 * @apiParam {String} new New password
	 *
	 * @apiError 401 Old password is incorrect
	 * @apiError 403 Account is disabled
	 * @apiError 404 Account doesn't exist
	 **/
	router.put('/members/password', Permission('Member.access'), async (ctx, next) => {

		let payload = ctx.request.body;

		// Check parameters
		if (payload['old'] === undefined || payload['new'] === undefined) {
			ctx.throw(400, {
				code: 'BadRequest',
				message: 'Bad request'
			});
		}

		try {
			// Verify member account
			await memberAgent.getMemberManager().changePassword(ctx.state.session.id, payload['old'], payload['new']);

			// Response
			ctx.body = {
				code: 'Success',
				message: 'Password was changed'
			};

		} catch(e) {

			switch(e.name) {
			case 'IncorrectOldPassword':
				ctx.throw(401, {
					code: 'IncorrectOldPassword',
					message: 'Incorrect Old Password'
				});

			case 'Disabled':
				ctx.throw(403, {
					code: 'AccountBlocked',
					message: 'Account was blocked'
				});

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
