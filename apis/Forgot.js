module.exports = (service) => {

	// Getting member system agent
	const memberAgent = service.getContext().get('Member')[service.memberAgent];
	const Permission = memberAgent.getPermissionMiddleware();

	// Create a new router
	const router = service.createRouter({
		prefix: '/api/v1'
	});

	// Set type to "API" for router
	router.use(service.routeType('API'));

	/**
	 * @api {post} /api/v1/members/forgot Request to reset password
	 * @apiName Forgot
	 * @apiGroup Member
	 *
	 * @apiParam {String} email member's email
	 *
	 * @apiError 403 Account is disabled
	 * @apiError 404 Account doesn't exist
	 * @apiError 422 Parameters are invalid
	 * @apiErrorExample {json} Error-Response:
	 *	HTTP/1.1 422 Validation Failed
	 *	{
	 *		code: 'ValidationFailed',
	 *		message: 'Validation Failed',
	 *		errors: [
	 *			{ field: 'email', code: 'required'  },
	 *		]
	 *	}
	 **/
	router.post('/members/forgot', async (ctx, next) => {

		const payload = ctx.request.body;

		try {
			// Verify member account
			const member = await memberAgent
				.getMemberManager()
				.sendPasswordResetEmail(payload);

			// Response
			ctx.body = {
				code: 'Success'
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
				ctx.throw(404, {
					code: 'NotExist',
					message: 'Account doesn\'t exist'
				});
			}

			throw e;
		}
	});

	/**
	 * @api {post} /api/v1/members/reset_password Reset password
	 * @apiName ResetPassword
	 * @apiGroup Member
	 *
	 * @apiHeader {String} authorization user's token
	 * @apiParam {String} password New password
	 *
	 * @apiError 403 Account is disabled
	 * @apiError 404 Account doesn't exist
	 * @apiError 422 Parameters are invalid
	 * @apiErrorExample {json} Error-Response:
	 *	HTTP/1.1 422 Validation Failed
	 *	{
	 *		code: 'ValidationFailed',
	 *		message: 'Validation Failed',
	 *		errors: [
	 *			{ field: 'password', code: 'required'  },
	 *		]
	 *	}
	 **/
	router.post('/members/reset_password', async (ctx, next) => {

		const payload = ctx.request.body;

		try {
			// Verify member account
			const member = await memberAgent
				.getMemberManager()
				.updatePasswordByEmail(ctx.state.session.email, payload.password);

			// Response
			ctx.body = {
				code: 'Success'
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
