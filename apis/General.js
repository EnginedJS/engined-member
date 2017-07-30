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
	 * @api {post} /api/v1/members/authorize Authorize account to sign in
	 * @apiName Authorize
	 * @apiGroup Member
	 *
	 * @apiParam {String} email member's email
	 * @apiParam {String} password password
	 *
	 * @apiSuccess {String} token Access token
	 * @apiError 400 {String} BadRequest
	 * @apiError 401 {String} NotExist Account doesn't exist
	 * @apiError 403 {String} Disabled Account is disabled
	 * @apiError 422 {Object} ValidationFailed Parameters are invalid
	 * @apiErrorExample {json} Error-Response:
	 *	{
	 *		message: 'Validation Failed',
	 *		errors: [
	 *			{ field: 'email', code: 1  }
	 *		]
	 *	}
	 */
	router.post('/members/authorize', async (ctx, next) => {

		if (!ctx.request.body)
			ctx.throw(400);

		let payload = ctx.request.body;

		// Create a package for restful API
		let pkg = new RestPack();

		try {
			// Verify member account
			let member = await memberAgent.getMemberManager().verify(payload);

			// Getting permissions
			let permissions = await memberAgent.getPermissionManager().getPermissions(member.id);

			// Prepare JWT package for user
			pkg
				.setData({
					token: memberAgent.generateJwtToken({
						id: member.id,
						name: member.name,
						email: member.email,
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
			case 'Disabled':
				ctx.throw(403);
			case 'NotExist':
				ctx.throw(401);
			case 'VerificationFailed':
				ctx.throw(422);
			}

			console.error(e);
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
