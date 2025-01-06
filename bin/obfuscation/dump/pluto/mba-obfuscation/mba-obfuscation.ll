; ModuleID = 'dump/pluto/main.ll'
source_filename = "main.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

@.str = private unnamed_addr constant [14 x i8] c"Phacomochere\00\00", align 1
@good_string = dso_local local_unnamed_addr global ptr @.str, align 8
@size_good_string = dso_local local_unnamed_addr global i32 0, align 4
@good_value = dso_local local_unnamed_addr global i64 7594306241854992217, align 8
@stderr = external local_unnamed_addr global ptr, align 8
@.str.1 = private unnamed_addr constant [32 x i8] c"Usage: %s <string> <hex_value>\0A\00", align 1
@str = private unnamed_addr constant [29 x i8] c"RootFunction returned false.\00", align 1
@str.4 = private unnamed_addr constant [28 x i8] c"RootFunction returned true.\00", align 1
@x = private global i32 -1791264953
@y = private global i32 -1483872858
@x.1 = private global i32 863590994
@y.2 = private global i32 947613177

; Function Attrs: nofree nounwind uwtable
define dso_local noundef i32 @main(i32 noundef %0, ptr nocapture noundef readonly %1) local_unnamed_addr #0 {
  %3 = load ptr, ptr @good_string, align 8, !tbaa !5
  %4 = tail call i64 @strlen(ptr noundef nonnull dereferenceable(1) %3) #5
  %5 = trunc i64 %4 to i32
  %6 = mul i32 1, %5
  %7 = add i32 0, %6
  %8 = xor i32 %5, -1
  %9 = and i32 %8, 1
  %10 = mul i32 -1, %9
  %11 = add i32 %7, %10
  %12 = add i32 %11, 1
  %13 = xor i32 %5, 1
  %14 = mul i32 -1, %13
  %15 = add i32 %12, %14
  %16 = or i32 %5, 1
  %17 = mul i32 1, %16
  %18 = add i32 %15, %17
  %19 = or i32 %5, -2
  %20 = mul i32 -1, %19
  %21 = add i32 %18, %20
  %22 = and i32 %5, 1
  %23 = xor i32 %22, -1
  %24 = mul i32 1, %23
  %25 = add i32 %21, %24
  %26 = mul i32 -803697111, %25
  %27 = add i32 %26, -1612780406
  %28 = mul i32 1542516249, %27
  %29 = add i32 %28, 1408408198
  %30 = add i32 %5, 1
  store i32 %29, ptr @size_good_string, align 4, !tbaa !9
  %31 = load i32, ptr @x, align 4
  %32 = load i32, ptr @y, align 4
  %33 = and i32 %31, %32
  %34 = mul i32 -2, %33
  %35 = add i32 0, %34
  %36 = or i32 %31, %32
  %37 = mul i32 1, %36
  %38 = add i32 %35, %37
  %39 = xor i32 %32, -1
  %40 = mul i32 1, %39
  %41 = add i32 %38, %40
  %42 = xor i32 %31, -1
  %43 = or i32 %42, %32
  %44 = mul i32 1, %43
  %45 = add i32 %41, %44
  %46 = and i32 %31, %32
  %47 = xor i32 %46, -1
  %48 = mul i32 -2, %47
  %49 = add i32 %45, %48
  %50 = add i32 %49, 3
  %51 = mul i32 -1756953097, %50
  %52 = add i32 %51, 1059381616
  %53 = mul i32 814566343, %52
  %54 = add i32 %53, -241634832
  %55 = icmp eq i32 %0, %54
  br i1 %55, label %60, label %56

56:                                               ; preds = %2
  %57 = load ptr, ptr @stderr, align 8, !tbaa !5
  %58 = load ptr, ptr %1, align 8, !tbaa !5
  %59 = tail call i32 (ptr, ptr, ...) @fprintf(ptr noundef %57, ptr noundef nonnull @.str.1, ptr noundef %58) #6
  br label %136

60:                                               ; preds = %2
  %61 = getelementptr inbounds ptr, ptr %1, i64 2
  %62 = load ptr, ptr %61, align 8, !tbaa !5
  %63 = tail call i64 @strtoull(ptr nocapture noundef %62, ptr noundef null, i32 noundef 16) #7
  %64 = getelementptr inbounds ptr, ptr %1, i64 1
  %65 = load ptr, ptr %64, align 8, !tbaa !5
  %66 = icmp eq ptr %65, null
  br i1 %66, label %134, label %67

67:                                               ; preds = %60
  %68 = load ptr, ptr @good_string, align 8, !tbaa !5
  %69 = tail call i64 @strlen(ptr noundef nonnull dereferenceable(1) %68) #5
  %70 = trunc i64 %69 to i32
  %71 = mul i32 1, %70
  %72 = add i32 0, %71
  %73 = add i32 %72, 1
  %74 = mul i32 537766661, %73
  %75 = add i32 %74, 2070160173
  %76 = mul i32 1888840141, %75
  %77 = add i32 %76, -181313545
  %78 = add i32 %70, 1
  store i32 %77, ptr @size_good_string, align 4, !tbaa !9
  %79 = load i32, ptr @x.1, align 4
  %80 = load i32, ptr @y.2, align 4
  %81 = xor i32 %79, -1
  %82 = and i32 %81, %80
  %83 = mul i32 -1, %82
  %84 = add i32 0, %83
  %85 = or i32 %79, %80
  %86 = xor i32 %85, -1
  %87 = mul i32 -1, %86
  %88 = add i32 %84, %87
  %89 = xor i32 %79, -1
  %90 = mul i32 1, %89
  %91 = add i32 %88, %90
  %92 = add i32 %91, 2147483647
  %93 = mul i32 124294767, %92
  %94 = add i32 %93, 1652255071
  %95 = mul i32 -1704490865, %94
  %96 = add i32 %95, -505631761
  %97 = icmp ult i32 %70, %96
  br i1 %97, label %98, label %129

98:                                               ; preds = %67
  %99 = sext i32 %77 to i64
  %100 = zext i32 %77 to i64
  %101 = load i8, ptr %65, align 1, !tbaa !11
  %102 = load i8, ptr %68, align 1, !tbaa !11
  %103 = icmp eq i8 %101, %102
  br i1 %103, label %104, label %124

104:                                              ; preds = %116, %98
  %105 = phi i64 [ %113, %116 ], [ 0, %98 ]
  %106 = or i64 %105, 1
  %107 = mul i64 1, %106
  %108 = add i64 1, %107
  %109 = add i64 %108, -2
  %110 = and i64 %105, 1
  %111 = xor i64 %110, -1
  %112 = mul i64 -1, %111
  %113 = add i64 %109, %112
  %114 = add nuw nsw i64 %105, 1
  %115 = icmp eq i64 %113, %100
  br i1 %115, label %129, label %116, !llvm.loop !12

116:                                              ; preds = %104
  %117 = getelementptr inbounds i8, ptr %65, i64 %113
  %118 = load i8, ptr %117, align 1, !tbaa !11
  %119 = getelementptr inbounds i8, ptr %68, i64 %113
  %120 = load i8, ptr %119, align 1, !tbaa !11
  %121 = icmp eq i8 %118, %120
  br i1 %121, label %104, label %122, !llvm.loop !12

122:                                              ; preds = %116
  %123 = icmp slt i64 %113, %99
  br label %124

124:                                              ; preds = %122, %98
  %125 = phi i1 [ true, %98 ], [ %123, %122 ]
  %126 = load i64, ptr @good_value, align 8
  %127 = icmp ne i64 %126, %63
  %128 = select i1 %125, i1 true, i1 %127
  br i1 %128, label %134, label %132

129:                                              ; preds = %104, %67
  %130 = load i64, ptr @good_value, align 8, !tbaa !15
  %131 = icmp eq i64 %130, %63
  br i1 %131, label %132, label %134

132:                                              ; preds = %129, %124
  %133 = tail call i32 @puts(ptr nonnull dereferenceable(1) @str.4)
  br label %136

134:                                              ; preds = %129, %124, %60
  %135 = tail call i32 @puts(ptr nonnull dereferenceable(1) @str)
  br label %136

136:                                              ; preds = %134, %132, %56
  %137 = phi i32 [ 1, %56 ], [ 0, %134 ], [ 0, %132 ]
  ret i32 %137
}

; Function Attrs: mustprogress nofree nounwind willreturn memory(argmem: read)
declare i64 @strlen(ptr nocapture noundef) local_unnamed_addr #1

; Function Attrs: nofree nounwind
declare noundef i32 @fprintf(ptr nocapture noundef, ptr nocapture noundef readonly, ...) local_unnamed_addr #2

; Function Attrs: mustprogress nofree nounwind willreturn
declare i64 @strtoull(ptr noundef readonly, ptr nocapture noundef, i32 noundef) local_unnamed_addr #3

; Function Attrs: nofree nounwind
declare noundef i32 @puts(ptr nocapture noundef readonly) local_unnamed_addr #4

attributes #0 = { nofree nounwind uwtable "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { mustprogress nofree nounwind willreturn memory(argmem: read) "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #2 = { nofree nounwind "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #3 = { mustprogress nofree nounwind willreturn "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #4 = { nofree nounwind }
attributes #5 = { nounwind willreturn memory(read) }
attributes #6 = { cold }
attributes #7 = { nounwind }

!llvm.module.flags = !{!0, !1, !2, !3}
!llvm.ident = !{!4}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{i32 8, !"PIC Level", i32 2}
!2 = !{i32 7, !"PIE Level", i32 2}
!3 = !{i32 7, !"uwtable", i32 2}
!4 = !{!"Ubuntu clang version 18.1.8 (++20240731024944+3b5b5c1ec4a3-1~exp1~20240731145000.144)"}
!5 = !{!6, !6, i64 0}
!6 = !{!"any pointer", !7, i64 0}
!7 = !{!"omnipotent char", !8, i64 0}
!8 = !{!"Simple C/C++ TBAA"}
!9 = !{!10, !10, i64 0}
!10 = !{!"int", !7, i64 0}
!11 = !{!7, !7, i64 0}
!12 = distinct !{!12, !13, !14}
!13 = !{!"llvm.loop.mustprogress"}
!14 = !{!"llvm.loop.unroll.disable"}
!15 = !{!16, !16, i64 0}
!16 = !{!"long", !7, i64 0}
