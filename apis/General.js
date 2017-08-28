module.exports = (service) => {

	// Getting member system agent
	const memberAgent = service.getContext().get('Member').getAgent(service.memberAgent);
	const Permission = memberAgent.getPermissionMiddleware();

	// Create a new router
	const router = service.createRouter({
		prefix: '/api/v1'
	});

	// Set type to "API" for router
	router.use(service.routeType('API'));

	/**
	 * @api {post} /api/v1/members/authenticate Sign in
	 * @apiName Authorize
	 * @apiGroup Member
	 *
	 * @apiParam {String} email member's email
	 * @apiParam {String} password password
	 *
	 * @apiSuccess {String} token Access token
	 *
	 * @apiError 400 Invalid parameters
	 * @apiError 401 Authentication failed
	 * @apiError 403 Account is disabled
	 **/
	router.post('/members/authenticate', async (ctx, next) => {

		const payload = ctx.request.body;

		try {
			// Verify member account
			const member = await memberAgent
				.getMemberManager()
				.verifyMember(payload);

			// Getting permissions
			const permissions = await memberAgent
				.getPermissionManager()
				.getPermissions(member.id);

			// Response
			ctx.body = {
				token: memberAgent.generateJwtToken({
					id: member.id,
					name: member.name,
					email: member.email,
					perms: permissions
				}),
				name: member.name,
				email: member.email
			};

		} catch(e) {

			switch(e.name) {
			case 'ValidationFailed':
				ctx.throw(400, {
					code: 'InvalidParameters',
					message: 'Invalid parameters'
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

			throw e;
		}
	});

	/**
	 * @api {post} /api/v1/members Sign up an account
	 * @apiName SignUp
	 * @apiGroup Member
	 *
	 * @apiParam {String} email member's email
	 * @apiParam {String} password password
	 *
	 * @apiSuccess (201) {String} token Access token
	 * @apiSuccess (201) {String} email email of the account
	 * @apiSuccess (201) {Array} perms permissions of the account
	 * @apiSuccessExample {json} Success-Response:
	 *	HTTP/1.1 201 Created
	 *	{
	 *		"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwibmFtZSI6IkZyZWQgQ2hpZW4iLCJlbWFpbCI6ImNmc2d",
	 *		"email": "fred@example.com",
	 *		"perms": [
	 *			"Member.access"
	 *		]
	 *	}
	 *
	 * @apiError 409 Member exists already
	 * @apiError 422 Parameters are invalid
	 * @apiErrorExample {json} Error-Response:
	 *	HTTP/1.1 422 Validation Failed
	 *	{
	 *		"code": "ValidationFailed",
	 *		"message": "Validation Failed",
	 *		"errors": [
	 *			{ field: "email", code: "required" },
	 *			{ field: 'passsword', code: 'invalid'  }
	 *		]
	 *	}
	 **/
	router.post('/members', async (ctx) => {

		const payload = ctx.request.body;

		try {

			// Verify member account
			const memberId = await memberAgent
				.getMemberManager()
				.createMember(payload);

			// Apply permissions
			const permissions = [
				'Member.access'
			];
			await memberAgent
				.getPermissionManager()
				.addPermission(memberId, permissions);

			// Response
			ctx.body = {
				token: memberAgent.generateJwtToken({
					id: memberId,
					name: payload.name,
					email: payload.email,
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

			case 'MemberExists':
				ctx.throw(409, {
					code: 'MemberExists',
					message: e.message
				});
			}

			throw e;
		}
	});

	return router;
};
