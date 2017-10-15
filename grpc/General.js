
module.exports = (service) => {

	const grpcAgent = service.getContext().get('gRPCServer').getAgent(service.opts.agentName);
	const router = grpcAgent.getRouter();

	router.rpc('/Member/Authenticate', async (ctx) => {

		let payload = ctx.req.body;

		const memberAgent = service.getContext().get('Member').getAgent(service.opts.memberAgent);

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
				ctx.throw(grpcAgent.status.INVALID_ARGUMENT, {
					code: 'InvalidParameters',
					message: 'Invalid parameters'
				});

			case 'Disabled':
				ctx.throw(grpcAgent.status.PERMISSION_DENIED, {
					code: 'AccountBlocked',
					message: 'Account was blocked'
				});

			case 'NotExist':
			case 'VerificationFailed':
				ctx.throw(grpcAgent.status.UNAUTHENTICATED, {
					code: 'AuthenticationFailed',
					message: 'Authentication failed'
				});
			}

			ctx.throw(grpcAgent.status.ABORTED, e);
		}
	});

	router.rpc('/Member/Create', async (ctx) => {

		let payload = ctx.req.body;

		const memberAgent = service.getContext().get('Member').getAgent(service.opts.memberAgent);

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
				}),
				name: payload.name,
				email: payload.email
			};

		} catch(e) {

			switch(e.name) {
			case 'ValidationFailed':
				ctx.throw(grpcAgent.status.INVALID_ARGUMENT, {
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
				ctx.throw(grpcAgent.status.ALREADY_EXISTS, {
					code: 'MemberExists',
					message: e.message
				});
			}

			ctx.throw(grpcAgent.status.ABORTED, e);
		}
	});
};
