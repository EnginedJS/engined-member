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
	 * @api {post} /api/v1/members/authenticate Authenticate account to sign in
	 * @apiName Authorize
	 * @apiGroup Member
	 *
	 * @apiParam {String} email member's email
	 * @apiParam {String} password password
	 *
	 * @apiSuccess {String} token Access token
	 * @apiError 400 {String} BadRequest
	 * @apiError 401 {String} AuthenticationFailed Authentication failed
	 * @apiError 403 {String} AccountBlocked Account is disabled
	 * @apiError 422 {Object} ValidationFailed Parameters are invalid
	 * @apiErrorExample {json} Error-Response:
	 *	{
	 *		code: 'ValidationFailed',
	 *		message: 'Validation Failed',
	 *		errors: [
	 *			{ field: 'email', code: 'required'  },
	 *			{ field: 'passsword', code: 'invalid'  }
	 *		]
	 *	}
	 */
	router.post('/members/authenticate', async (ctx, next) => {

		let payload = ctx.request.body;

		try {
			// Verify member account
			let member = await memberAgent.getMemberManager().verify(payload);

			// Getting permissions
			let permissions = await memberAgent.getPermissionManager().getPermissions(member.id);

			// Prepare JWT package for user
			ctx.body = {
				token: memberAgent.generateJwtToken({
					id: member.id,
					name: member.name,
					email: member.email,
					perms: permissions
				})
			};

		} catch(e) {

			switch(e.name) {
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

			case 'Disabled':
				ctx.throw(403, {
					code: 'AccountBlocked',
					message: 'Account was blocked'
				});
			case 'NotExist':
			case 'VerificationFailed':
				ctx.throw(401, {
					code: 'AuthenticationFailed',
					message: 'Authentication failed'
				});
			}
		}
	});

	/*
	 * @api {post} /api/v1/members Sign up an account
	 * @apiName SignUp
	 * @apiGroup Member
	 *
	 * @apiParam {String} email member's email
	 * @apiParam {String} password password
	 *
	 * @apiSuccess {String} token Access token
	 * @apiError 400 {String} BadRequest
	 * @apiError 409 {String} MemberExistsAlready
	 * @apiError 422 {Object} ValidationFailed Parameters are invalid
	 * @apiErrorExample {json} Error-Response:
	 *	{
	 *		message: 'Validation Failed',
	 *		errors: [
	 *			{ field: 'email', code: 1  }
	 *		]
	 *	}
	 */
	router.post('/members', async (ctx) => {

		if (!ctx.request.body)
			ctx.throw(400);

		let payload = ctx.request.body;

		// Create a package for restful API
		let pkg = new RestPack();

		try {

			// Verify member account
			let memberId = await memberAgent.getMemberManager().createMember(payload);

			// Apply permissions
			let permissions = [
				'Member.access'
			];
			await memberAgent.getPermissionManager().addPermission(memberId, permissions);

			// Prepare JWT package for user
			pkg
				.setData({
					token: memberAgent.generateJwtToken({
						id: memberId,
						email: payload.email,
						perms: permissions
					})
				})
				.sendKoa(ctx);
		} catch(e) {

			switch(e.name) {
			case 'ValidationFailed':
				pkg.setStatus(RestPack.Status.ValidationFailed);

				e.errors.reduce((pkg, error) => {
					switch(error.type) {
					case 'any.required':
						pkg.appendError(error.field, RestPack.Code.Required);
						break;
					default:
						pkg.appendError(error.field, RestPack.Code.Invalid);
					}

					return pkg;
				}, pkg);

				pkg.sendKoa(ctx);
				break;

			case 'MemberExists':
				ctx.throw(409, e.message);
			case 'MemberCreationFailed':
				ctx.throw(500);
			default:
				console.error(e);
			}
		}
	});

	return router;
};
