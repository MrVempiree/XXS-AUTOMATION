import { Router, type IRouter } from "express";
import healthRouter from "./health";
import scanRouter from "./scan";
import scanStreamRouter from "./scan-stream";
import adminRouter from "./admin";
import licenseRouter from "./license";
import sqliRouter from "./sqli";
import collectRouter from "./collect";

const router: IRouter = Router();

router.use(healthRouter);
router.use(scanRouter);
router.use(scanStreamRouter);
router.use(adminRouter);
router.use(licenseRouter);
router.use(sqliRouter);
router.use(collectRouter);

export default router;
