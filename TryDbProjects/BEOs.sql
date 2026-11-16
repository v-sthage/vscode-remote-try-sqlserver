CREATE TABLE [dbo].[BEOs]
(
    [Id] [int] NOT NULL,
	[EventID] [int] NOT NULL,
	[Location] [nvarchar](50) NOT NULL,
	[StartTime] [time](7) NOT NULL,
	[EndTime] [time](7) NOT NULL,
	[Date] [date] NOT NULL,
	[TechAssigned] [uniqueidentifier] NULL,
	[Zone] [nchar](10) NULL,
	[ImageLink] [nvarchar](50) NULL,
	[Comments] [ntext] NULL,
	[Available] [nvarchar](50) NOT NULL,
	[TurnTime] [int] NULL,
	[OpenTime] [time](7) NULL,
	[SetByTime] [time](7) NULL
    CONSTRAINT [PK_BEOs] PRIMARY KEY CLUSTERED ([Id])
);
