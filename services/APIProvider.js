const Router = require('koa-router');
const { RouterService } = require('engined-http');
const RestPack = require('restpack');
const MemberAPI = require('../lib/Member');
const PermissionAPI = require('../lib/Permission');

const createRouter = (service) => {

	// Getting member system agent
	const memberAPI = MemberAPI(service);
	const permissionAPI = PermissionAPI(service);

	// Create a new router
	let router = Router({
		prefix: '/api/v1/member'
	});

	/*
	 * @api {post} /api/v1/member/auth Authorize account to sign in
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
	router.post('/auth', async (ctx, next) => {

		if (!ctx.request.body)
			ctx.throw(400);

		// Create a package for restful API
		let pkg = new RestPack();

		let payload = ctx.request.body;
		let email = payload.email;
		let password = payload.password || '';

		if (!email) {
			pkg
				.setStatus(RestPack.Status.ValidationFailed)
				.appendError('email', RestPack.Code.Required)
				.sendKoa(ctx);

			return;
		}

		// Getting member system agent
		let agent = ctx.enginedContext.get('Member')[service.memberAgent];

		try {
			// Verify member account
			let member = await memberAPI.verify(email, password);

			// Getting permissions
			let permissions = await permissionAPI.getPermissions(member.id);

			// Prepare JWT package for user
			pkg
				.setData({
					token: agent.generateJwtToken({
						id: member.id,
						name: member.name,
						email: member.email,
						perms: permissions
					})
				})
				.sendKoa(ctx);
		} catch(e) {

			switch(e.name) {
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
	 * @api {post} /api/v1/member/signup Sign up an account
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
	router.post('/signup', async (ctx) => {

		if (!ctx.request.body)
			ctx.throw(400);

		// Create a package for restful API
		let pkg = new RestPack();

		let payload = ctx.request.body;
		let email = payload.email;

		if (!email) {
			pkg
				.setStatus(RestPack.Status.ValidationFailed)
				.appendError('email', RestPack.Code.Required)
				.sendKoa(ctx);

			return;
		}

		try {

			// Getting member system agent
			let agent = ctx.enginedContext.get('Member')[service.memberAgent];

			// Verify member account
			let memberId = await memberAPI.createMember(email, payload.password);

			// Apply permissions
			let permissions = [
				'Member.access'
			];
			await agent.getPermissionManager().addPermission(memberId, permissions);

			// Prepare JWT package for user
			pkg
				.setData({
					token: agent.generateJwtToken({
						id: memberId,
						email: email,
						perms: permissions
					})
				})
				.sendKoa(ctx);
		} catch(e) {

			switch(e.name) {
			case 'MemberExists':
				ctx.throw(409, e.message);
			case 'MemberCreationFailed':
				ctx.throw(500);
			}

			console.error(e);
		}
	});

	return router;
};

module.exports = (opts) => class extends RouterService() {

	constructor(context) {
		super(context);

		this.memberAgent = opts.memberAgent || 'default';
	}

	async setupRoutes() {
		return createRouter(this);
	}
};
