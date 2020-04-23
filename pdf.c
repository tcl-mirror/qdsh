#include <string.h>
#include <tcl.h>
/*#include <stdio.h>*/

#include "qdsh.h"

typedef struct {
    int ch2;
    int wpx;
} Kern;

typedef struct {
    int wx;
    Kern *kern;
} C;

typedef struct {
    int numChars;
    int start;
    int last;
    Kern *kern;
    C chars[1];
} Metrics;

static void
deleteTextDrawer(ClientData cd)
{
    Metrics *metrics = (Metrics *)cd;
    ckfree(metrics->kern);
    ckfree(metrics);
}

static void
hex(Tcl_DString *dsPtr, unsigned int n)
{
    int u, l;
    char b[2];

    u = (n >> 4) & 0xf;
    b[0] = u + (u < 10 ? '0' : ('a'-10));
    l = n & 0xf;
    b[1] = l + (l < 10 ? '0' : ('a'-10));
    Tcl_DStringAppend(dsPtr, b, 2);
}

static void
decNonneg(Tcl_DString *dsPtr, int n)
{
    char c;

    if (n >= 10) {
	decNonneg(dsPtr, n / 10);
	n %= 10;
    }
    c = '0' + n;
    Tcl_DStringAppend(dsPtr, &c, 1);
}

static void
dec(Tcl_DString *dsPtr, int n)
{
    char c;
    
    if (n < 0) {
	c = '-';
	Tcl_DStringAppend(dsPtr, &c, 1);
	n = -n;
    }
    decNonneg(dsPtr, n);
}

static int
textDrawerHandler(ClientData cd, Tcl_Interp *interp,
                  int objc, Tcl_Obj *const objv[])
{
    int numLines, i;
    Tcl_Obj *res, **lineWidths;
    char *str, *cp, buf[2];
    char *endStr = ">] TJ";
    static Tcl_DString ds;
    Metrics *metrics = (Metrics *)cd;

    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "text lengths");
        return TCL_ERROR;
    }
    if (Tcl_ListObjGetElements(interp, objv[2], &numLines, &lineWidths) != TCL_OK) {
        return TCL_ERROR;
    }
    
    str = Tcl_GetString(objv[1]);
    res = Tcl_NewObj();
    cp = str;
    Tcl_DStringInit(&ds);

#define PUT2(a, b)                                              \
    do {                                                        \
        buf[0] = a; buf[1] = b; Tcl_DStringAppend(&ds, buf, 2); \
    } while (0);

    PUT2('[', '<');
    for (i = 0; i < numLines; i++) {
        char *brkPos;
        int brkStrLen = 0, brkWidth = 0, curWidth = 0, lineWidth;
        
        if (Tcl_GetIntFromObj(interp, lineWidths[i], &lineWidth) != TCL_OK) {
            Tcl_DStringFree(&ds);
            Tcl_DecrRefCount(res);
            return TCL_ERROR;
        }

        brkPos = cp;
        for (;;) {
	    char c0;
            C *c;
            Kern *k;
            int adv;
            
            if (*cp == '\0' || *cp == '\n') {
                Tcl_DStringAppend(&ds, endStr, -1);
                Tcl_ListObjAppendElement(NULL, res, Tcl_NewIntObj(curWidth));
                Tcl_ListObjAppendElement(NULL, res, Tcl_NewStringObj(Tcl_DStringValue(&ds),
                                                                     Tcl_DStringLength(&ds)));
		if (*cp == '\n') {
		    Tcl_DStringSetLength(&ds, 0);
		    PUT2('[', '<');
		    cp++;
		    break;
		}

		Tcl_DStringFree(&ds);
		Tcl_SetObjResult(interp, res);
		return TCL_OK;
            }
                
            if (*cp == ' ') {
                brkWidth = curWidth;
                brkStrLen = Tcl_DStringLength(&ds);
                brkPos = cp;
            }

	    c0 = *cp;
	    if (c0 > metrics->last || c0 < metrics->start)
		c0 = 'X';
            
            hex(&ds, c0);
            c = &metrics->chars[c0 - metrics->start];
            adv = c->wx;
            k = c->kern;
            if (cp[1] != '\0' && k != NULL) {
                for (;;) {
                    if (k->ch2 == cp[1]) {
                        PUT2('>', ' ');
			dec(&ds, -k->wpx);
                        PUT2(' ', '<');
                        adv += k->wpx;
                        break;
                    }
                    k++;
                    if (k->ch2 == -1) {
                        break;
                    }
                }
            }
            curWidth += adv;
            if (lineWidth != -1 && curWidth > lineWidth) {
                /* Back up to saved position */
                Tcl_DStringSetLength(&ds, brkStrLen);
                Tcl_DStringAppend(&ds, endStr, -1);
                Tcl_ListObjAppendElement(NULL, res, Tcl_NewIntObj(brkWidth));
                Tcl_ListObjAppendElement(NULL, res, Tcl_NewStringObj(Tcl_DStringValue(&ds),
                                                                     Tcl_DStringLength(&ds)));
                cp = brkPos+1; /* skip the space */
                Tcl_DStringSetLength(&ds, 0);
                PUT2('[', '<');
                break;
            }
            cp++;
        }
    }

    /* Not reached */
    return TCL_OK;

#if 0
    do {
        int i, start, last;
        Kern *kp;

        start = metrics->start;
        last = metrics->last;
        
        for (i = 0; i < last-start+1; i++) {
            if (metrics->chars[i].wx == 0) continue;
            fprintf(stderr, "C:%d WX:%d\n", metrics->start+i, metrics->chars[i].wx);
            if (metrics->chars[i].kern) {
                kp = metrics->chars[i].kern;
                while (kp->ch2 != -1) {
                    fprintf(stderr, "    C2:%d WPX:%d\n", kp->ch2, kp->wpx);
                    kp++;
                }
            }
        }
    } while (0);
    
    return TCL_OK;
#endif
}

static int
textDrawerCmd(ClientData cd, Tcl_Interp *interp,
              int objc, Tcl_Obj *const objv[])
{
    int numChars, c, i, j, len, numKern, totalKerns, start, last;
    Tcl_Obj **chars, **vals, **kernList;
    Kern *kp;
    C *cp;
    Metrics *metrics;

    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "cmd metrics");
        return TCL_ERROR;
    }

    if (Tcl_ListObjGetElements(NULL, objv[2], &numChars, &chars) != TCL_OK || numChars < 1) {
        goto error;
    }
    totalKerns = 0;
    for (i = 0; i < numChars; i++) {
        if (Tcl_ListObjGetElements(NULL, chars[i], &len, &vals) != TCL_OK ||
            len != 4 ||
            Tcl_GetIntFromObj(NULL, vals[0], &c) != TCL_OK ||
            Tcl_ListObjGetElements(NULL, vals[3], &numKern, &kernList) != TCL_OK) {
            goto error;
        }
        if (numKern > 0) {
            totalKerns += numKern/2 + 1; /* final -1 */
        }
    }

    /* Calculate start and last, check that everything is in range */
    Tcl_ListObjGetElements(NULL, chars[0], &len, &vals);
    Tcl_GetIntFromObj(NULL, vals[0], &start);
    Tcl_ListObjGetElements(NULL, chars[numChars-1], &len, &vals);
    Tcl_GetIntFromObj(NULL, vals[0], &last);
    if ((last - start) < 1 || (last - start) > 255) {
        goto error;
    }
    for (i = 0; i < numChars; i++) {
        Tcl_ListObjGetElements(NULL, chars[i], &len, &vals);
        Tcl_GetIntFromObj(NULL, vals[0], &c);
        if (c < start || c > last) goto error;
    }

    /* Allocate structures */
    metrics = ckalloc(sizeof(Metrics) + sizeof(C)*(last-start)); /* tricky */
    metrics->numChars = numChars;
    metrics->start = start;
    metrics->last = last;
    metrics->kern = ckalloc(sizeof(Kern) * totalKerns);
    for (i = 0; i < last-start+1; i++) {
        metrics->chars[i].wx = 0;
        metrics->chars[i].kern = NULL;
    }

    /* Fill in data */
    kp = metrics->kern;
    for (i = 0; i < numChars; i++) {
        Tcl_ListObjGetElements(NULL, chars[i], &len, &vals);
        Tcl_GetIntFromObj(NULL, vals[0], &c);
        cp = &metrics->chars[c-start];
        if (Tcl_GetIntFromObj(NULL, vals[1], &cp->wx) != TCL_OK) {
            goto error;
        }

        Tcl_ListObjGetElements(NULL, vals[3], &numKern, &kernList);
	if (numKern == 0)
	    continue;
	
	cp->kern = kp;
	for (j = 0; j < numKern/2; j++) {
	    if (Tcl_GetIntFromObj(NULL, kernList[j*2], &cp->kern[j].ch2) != TCL_OK ||
		Tcl_GetIntFromObj(NULL, kernList[j*2+1], &cp->kern[j].wpx) != TCL_OK) {
		goto error;
	    }
	}
	cp->kern[j].ch2 = -1;
	cp->kern[j].wpx = -1;
	kp += numKern/2 + 1;
    }

    return ckCreateCmd(interp, Tcl_GetString(objv[1]), textDrawerHandler,
		       (ClientData)metrics, deleteTextDrawer)
	? TCL_OK : TCL_ERROR;
    
error:
    return errorMsg(interp, "invalid metrics data");
}

static int
pngPredictCmd(ClientData cd, Tcl_Interp *interp,
	      int objc, Tcl_Obj *const objv[])
{
    Tcl_Obj *bytesPtr, *resPtr;
    char *sub;
    unsigned char *src, *dst;
    int dir, colors, height, width, depth, result, bytes,
	stride, i, j, scanlineSize;
    
    if (objc != 6) {
	Tcl_WrongNumArgs(interp, 1, objv, "subcommand colors depth width bytes");
	return TCL_ERROR;
    }

    /* Get direction */
    sub = Tcl_GetString(objv[1]);
    if (strcmp(sub, "filter") == 0) {
	dir = 1;
    } else if (strcmp(sub, "unfilter") == 0) {
	dir = 0;
    } else {
	Tcl_SetObjResult(interp,  Tcl_ObjPrintf("bad subcommand \"%s\"", sub));
	return TCL_ERROR;
    }

    /* Get colors */
    result = Tcl_GetIntFromObj(interp, objv[2], &colors);
    if (result != TCL_OK)
	return result;
    if (colors < 1) {
	Tcl_SetObjResult(interp, Tcl_ObjPrintf("bad number of colors %d", colors));
	return TCL_ERROR;
    }

    /* Get depth */
    result = Tcl_GetIntFromObj(interp, objv[3], &depth);
    if (result != TCL_OK)
	return result;
    if (depth != 1 && depth != 2 && depth != 4 && depth != 8 && depth != 16) {
	Tcl_SetObjResult(interp, Tcl_ObjPrintf("bad depth %d", depth));
	return TCL_ERROR;
    }

    /* Get width */
    result = Tcl_GetIntFromObj(interp, objv[4], &width);
    if (result != TCL_OK)
	return result;
    if (width <= 0) {
	Tcl_SetObjResult(interp, Tcl_ObjPrintf("bad width %d", width));
	return TCL_ERROR;
    }

    bytesPtr = objv[5];
    src = Tcl_GetByteArrayFromObj(bytesPtr, &bytes);

    stride = (width * colors * depth + 7) >> 3;
    scanlineSize = stride + 1;
    
    if (bytes % scanlineSize != 0) {
	Tcl_SetObjResult(interp,
			 Tcl_ObjPrintf("expected multiple of %d bytes, got %d", scanlineSize,
				       bytes));
	return TCL_ERROR;
    }

    height = bytes / scanlineSize;
    resPtr = Tcl_NewByteArrayObj(NULL, stride*height);
    dst = Tcl_GetByteArrayFromObj(resPtr, NULL);

    if (dir) {
	goto unimplemented;
    } else {
	for (j = 0; j < height; j++) {
	    switch (*src++) {
	    case 1:
		goto unimplemented;
	    case 2:
		if (j == 0) {
		    memcpy(dst, src, stride);
		    dst += stride;
		    src += stride;
		} else {
		    for (i = 0; i < stride; i++) {
			*dst = *src + *(dst-stride);
			dst++;
			src++;
		    }
		}
		break;
	    case 3:
	    case 4:
	    case 5:
		goto unimplemented;
	    default:
		memcpy(dst, src, stride);
		dst += stride;
		src += stride;
	    }
	}
    }

    Tcl_InvalidateStringRep(bytesPtr);
    Tcl_SetObjResult(interp, resPtr);
    return TCL_OK;
    
unimplemented:	
    Tcl_SetObjResult(interp, Tcl_NewStringObj("not yet implemented", -1));
    return TCL_ERROR;
}

void
pdfInit(Tcl_Interp *interp)
{
    Tcl_CreateObjCommand(interp, "pdf::text_drawer", textDrawerCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "pdf::png_predict", pngPredictCmd, NULL, NULL);
}
