#pragma once
class IObjectFormatParser
{
public:
	IObjectFormatParser();
	virtual ~IObjectFormatParser();

	virtual void getRttiInfo() = 0;
	virtual void clearInfo() = 0;
};

extern IObjectFormatParser *objectFormatParser;
