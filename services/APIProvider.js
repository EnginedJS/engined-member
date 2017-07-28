const Router = require('koa-router');
const { RouterService } = require('engined-http');
const RestPack = require('restpack');
const MemberAPI = require('../lib/Member');
const PermissionAPI = require('../lib/Permission');

const createRouter = (service) => {

	// Getting member system agent
	const memberAPI = MemberAPI(service);
	const permissionAPI = PermissionAPI(service);
	const Permission = service.getContext().get('Member')[service.memberAgent].getPermissionMiddleware();

	// Create a new router
	let router = Router({
		prefix: '/api/v1'
	});

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

		// Getting member system agent
		let agent = ctx.enginedContext.get('Member')[service.memberAgent];

		try {
			// Verify member account
			let member = await memberAPI.verify(payload);

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

			// Getting member system agent
			let agent = ctx.enginedContext.get('Member')[service.memberAgent];

			// Verify member account
			let memberId = await memberAPI.createMember(payload);

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

	/*
	 * @api {get} /api/v1/members/profile Getting users profile
	 * @apiName GetMemberProfile
	 * @apiGroup Member
	 *
	 * @apiHeader {String} authorization users token
	 *
	 * @apiSuccess {String} token Access token
	 * @apiError 400 {String} BadRequest
	 * @apiError 401 {String} NotExist Account doesn't exist
	 * @apiError 403 {String} Disabled Account is disabled
	 */
	router.get('/members/profile', Permission('Member.access'), async (ctx, next) => {

		// Create a package for restful API
		let pkg = new RestPack();

		// Getting member system agent
		let agent = ctx.enginedContext.get('Member')[service.memberAgent];

		try {
			// Verify member account
			let member = await memberAPI.getProfile(ctx.state.session.id);


			// Prepare JWT package for user
			pkg
				.setData(member)
				.sendKoa(ctx);
		} catch(e) {

			switch(e.name) {
			case 'NotExist':
				ctx.throw(401);
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
